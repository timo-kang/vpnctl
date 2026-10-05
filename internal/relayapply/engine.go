// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayplan"
)

type envelope struct {
	Journal Journal `json:"journal"`
	Digest  string  `json:"sha256"`
}

func digest(j Journal) string {
	b, _ := json.Marshal(j)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// An abstract Unix socket is a nonblocking, namespace-wide advisory lock.
// The kernel releases it on process death and CLOEXEC prevents child leakage.
var ErrKernelBusy = errors.New("another process owns the relay apply lock in this network namespace")

func kernelLock() (func(), error) {
	return namedKernelLock("@vpnctl.relay-apply.v1")
}
func namedKernelLock(name string) (func(), error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, ErrKernelBusy
		}
		return nil, fmt.Errorf("relay apply namespace lock: %w", err)
	}
	return func() { unix.Close(fd) }, nil
}
func domain() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	st, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("network namespace identity unavailable")
	}
	return fmt.Sprintf("%s:%d:%d", strings.TrimSpace(string(b)), s.Dev, s.Ino), nil
}
func Open(cache *relaycache.Store, underlays []relayplan.Underlay) (*Engine, error) {
	unlock, err := kernelLock()
	if err != nil {
		return nil, err
	}
	d, err := domain()
	if err != nil {
		unlock()
		return nil, err
	}
	e, err := open(cache, underlays, d, kernel{run: command})
	if err != nil {
		unlock()
		return nil, err
	}
	e.unlock = unlock
	return e, nil
}
func open(cache *relaycache.Store, underlays []relayplan.Underlay, domain string, b backend) (*Engine, error) {
	r, err := cache.Status()
	if err != nil {
		return nil, err
	}
	e := &Engine{cache: cache, underlays: underlays, backend: b, save: cache.SaveApplyJournal, journal: Journal{Version: 1, Node: r.NodeID, Domain: domain, Entries: []Entry{}}}
	e.targets = targetKernel{kernel{run: command}}
	raw, err := cache.ApplyJournal()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return e, nil
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&env) != nil || dec.Decode(new(any)) != io.EOF || env.Digest != digest(env.Journal) {
		return nil, errors.New("apply journal is corrupt")
	}
	j := env.Journal
	if err = validateTargetGuards(j.Targets, j.Node); err != nil {
		return nil, err
	}
	if j.Version != 1 || j.Node != r.NodeID || j.Domain != domain || len(j.Entries) > maxEntries || j.Entries == nil {
		return nil, errors.New("apply journal identity or kernel domain mismatch")
	}
	seen := map[string]bool{}
	for _, entry := range j.Entries {
		if err = validateEntry(entry, j.Node); err != nil {
			return nil, err
		}
		if seen[entry.Candidate.PathID] {
			return nil, errors.New("duplicate journal path")
		}
		seen[entry.Candidate.PathID] = true
	}
	e.journal = j
	return e, nil
}
func (e *Engine) approval(ctx context.Context, path, controller string) (Entry, time.Time, error) {
	r, err := e.cache.Status()
	if err != nil {
		return Entry{}, time.Time{}, err
	}
	p, err := relayplan.Build(ctx, r.NodeID, controller, r, e.underlays, e.collector)
	if err != nil {
		return Entry{}, time.Time{}, err
	}
	if p.State != "eligible" {
		return Entry{}, time.Time{}, errors.New("no eligible approved candidate")
	}
	for _, c := range p.Paths {
		if c.PathID == path && c.State == "eligible" && c.Pin != nil {
			entry := Entry{Controller: p.ControllerID, Node: p.NodeID, Generation: p.Generation, ApprovalUntil: r.Catalog.ExpiresAt, Candidate: c, Phase: "preparing"}
			return entry, p.ValidUntil, nil
		}
	}
	return Entry{}, time.Time{}, errors.New("requested path is not eligible")
}
func (e *Engine) stillApproved(entry Entry) error {
	r, err := e.cache.Status()
	if err != nil {
		return err
	}
	if !r.UsableCache || r.Validity != "valid" || r.ControllerID != entry.Controller || r.ObservedGeneration != entry.Generation || !time.Now().Before(entry.ApprovalUntil) {
		return errors.New("approval expired or changed")
	}
	for _, p := range r.Paths {
		if p.PathID == entry.Candidate.PathID && p.State == "bound" && p.PublicKey == entry.Candidate.PublicKey && p.InnerAddress == entry.Candidate.InnerAddress {
			return nil
		}
	}
	return errors.New("binding unavailable")
}
func (e *Engine) Prepare(ctx context.Context, path, controller string) (Result, error) {
	return e.prepare(ctx, path, controller, false)
}

// PrepareProbe adds approved target routes and a source-/32 rule inside the
// owned candidate table. It permits explicit-source probes, not unbound apps.
func (e *Engine) PrepareProbe(ctx context.Context, path, controller string) (Result, error) {
	return e.prepare(ctx, path, controller, true)
}
func (e *Engine) prepare(ctx context.Context, path, controller string, probeRouting bool) (Result, error) {
	if e.uncertain {
		return failure(path, "reopen_journal_required", relaycache.ErrUncertain)
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	entry, until, err := e.approval(ctx, path, controller)
	if err != nil {
		return failure(path, "approval_or_inventory_unavailable", err)
	}
	entry.ProbeRouting = probeRouting
	if i := e.index(path); i >= 0 {
		old := e.journal.Entries[i]
		if old.Phase != "prepared" {
			return failure(path, "pending_journal", ErrRecovery)
		}
		if old.ProbeRouting != entry.ProbeRouting || old.Controller != entry.Controller || !reflect.DeepEqual(old.Candidate, entry.Candidate) {
			return failure(path, "release_previous_candidate_first", ErrConflict)
		}
		ready, err := e.backend.Check(ctx, old, false)
		if err != nil || !ready {
			return failure(path, "kernel_state_changed", errors.Join(ErrRecovery, err))
		}
		if err = inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
			return failure(path, "inventory_changed", err)
		}
		if !time.Now().Before(until) || ctx.Err() != nil {
			return failure(path, "plan_expired", ErrRecovery)
		}
		if err = e.stillApproved(entry); err != nil {
			return failure(path, "approval_changed", err)
		}
		old.Generation, old.ApprovalUntil = entry.Generation, entry.ApprovalUntil
		e.journal.Entries[i] = old
		if err = e.persist(); err != nil {
			return failure(path, "journal_save_failed", err)
		}
		r := result("prepared", path, "")
		r.KernelReady = true
		return r, nil
	}
	if len(e.journal.Entries) >= maxEntries {
		return failure(path, "candidate_limit", ErrRecovery)
	}
	entry.Alias, entry.Metric, entry.LinkIndex, err = token()
	if err != nil {
		return failure(path, "owner_unavailable", err)
	}
	if err = validateEntry(entry, e.journal.Node); err != nil {
		return failure(path, "invalid_candidate", err)
	}
	if _, err = e.backend.Check(ctx, entry, true); err != nil {
		return failure(path, "resource_conflict_or_inventory_error", err)
	}
	if err = inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
		return failure(path, "inventory_changed", err)
	}
	if !time.Now().Before(until) || ctx.Err() != nil {
		return failure(path, "plan_expired", ErrRecovery)
	}
	if err = e.stillApproved(entry); err != nil {
		return failure(path, "approval_changed", err)
	}
	e.journal.Entries = append(e.journal.Entries, entry)
	// Intent must be durable BEFORE the first mutation. Any storage error stops
	// this operation, including a rename whose directory sync was uncertain.
	if err = e.persist(); err != nil {
		return failure(path, "journal_save_failed", err)
	}
	steps := []string{"link", "tag", "guard", "endpoint", "rule", "address", "wg", "up"}
	if probeRouting {
		steps = append(steps, "probe-targets", "probe-source")
	}
	for _, step := range steps {
		if ctx.Err() != nil {
			err = ctx.Err()
			break
		}
		if !time.Now().Before(until) {
			err = errors.New("plan expired during prepare")
			break
		}
		if err = e.stillApproved(entry); err != nil {
			break
		}
		if step == "up" {
			if err = inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
				break
			}
		}
		if step == "wg" {
			err = e.cache.WithPathKey(entry.Controller, entry.Generation, path, entry.Candidate.PublicKey, func(key string) error { return e.backend.Step(ctx, entry, step, key) })
		} else {
			err = e.backend.Step(ctx, entry, step, "")
		}
		if err != nil {
			err = fmt.Errorf("apply step %s: %w", step, err)
			break
		}
	}
	if err == nil {
		var ready bool
		ready, err = e.backend.Check(ctx, entry, false)
		if err == nil && !ready {
			err = errors.New("kernel readback incomplete")
		}
	}
	if err == nil {
		err = e.stillApproved(entry)
	}
	if err == nil {
		err = inventoryMatches(ctx, entry, e.underlays, e.collector)
	}
	if err == nil {
		err = e.stillApproved(entry)
	}
	if err == nil && (!time.Now().Before(until) || ctx.Err() != nil) {
		err = errors.New("prepare deadline or observation validity exceeded")
	}
	if err != nil {
		// A canceled caller still gets a bounded independent cleanup attempt.
		cleanup, cancel := context.WithTimeout(context.Background(), MaxDuration)
		defer cancel()
		if cleanupErr := e.backend.Remove(cleanup, entry); cleanupErr != nil {
			return failure(path, "recovery_required", errors.Join(err, cleanupErr))
		}
		e.journal.Entries = e.journal.Entries[:len(e.journal.Entries)-1]
		if saveErr := e.persist(); saveErr != nil {
			return failure(path, "journal_save_failed_after_cleanup", saveErr)
		}
		return failure(path, "prepare_failed_rolled_back", err)
	}
	e.journal.Entries[len(e.journal.Entries)-1].Phase = "prepared"
	if err = e.persist(); err != nil {
		return failure(path, "recovery_required", err)
	}
	r := result("prepared", path, "")
	r.KernelReady = true
	return r, nil
}
func (e *Engine) Release(ctx context.Context, path string) (Result, error) {
	if e.uncertain {
		return failure(path, "reopen_journal_required", relaycache.ErrUncertain)
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	i := e.index(path)
	if i < 0 {
		return failure(path, "path_not_owned", ErrConflict)
	}
	entry := e.journal.Entries[i]
	entry.Phase = "releasing"
	e.journal.Entries[i] = entry
	if err := e.persist(); err != nil {
		return failure(path, "journal_save_failed", err)
	}
	if err := e.backend.Remove(ctx, entry); err != nil {
		return failure(path, "recovery_required", err)
	}
	e.journal.Entries = append(e.journal.Entries[:i], e.journal.Entries[i+1:]...)
	if err := e.persist(); err != nil {
		return failure(path, "journal_save_failed_after_cleanup", err)
	}
	return result("released", path, ""), nil
}
func (e *Engine) Recover(ctx context.Context) (Result, error) {
	if e.uncertain {
		return failure("", "reopen_journal_required", relaycache.ErrUncertain)
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	for i := 0; i < len(e.journal.Entries); {
		entry := e.journal.Entries[i]
		if entry.Phase == "prepared" {
			i++
			continue
		}
		if _, err := e.Release(ctx, entry.Candidate.PathID); err != nil {
			return failure(entry.Candidate.PathID, "recovery_required", err)
		}
	}
	return e.Inspect(ctx)
}
func (e *Engine) Inspect(ctx context.Context) (Result, error) {
	if e.uncertain {
		return failure("", "reopen_journal_required", relaycache.ErrUncertain)
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	r := result("empty", "", "")
	var all error
	for _, entry := range e.journal.Entries {
		p := PathResult{PathID: entry.Candidate.PathID, Phase: entry.Phase}
		ready, err := e.backend.Check(ctx, entry, false)
		switch {
		case err != nil:
			p.Reason = "kernel_conflict_or_unavailable"
		case entry.Phase != "prepared":
			p.Reason = "pending_journal"
			err = ErrRecovery
		case !ready:
			p.Reason = "kernel_state_incomplete"
			err = ErrRecovery
		default:
			err = e.stillApproved(entry)
			if err != nil {
				p.Reason = "approval_expired_or_changed"
			} else if err = inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
				p.Reason = "inventory_changed"
			} else if err = e.stillApproved(entry); err != nil {
				p.Reason = "approval_expired_or_changed"
			} else if err = ctx.Err(); err != nil {
				p.Reason = "inspection_deadline"
			} else {
				p.KernelReady = true
			}
		}
		all = errors.Join(all, err)
		r.Paths = append(r.Paths, p)
	}
	if len(r.Paths) > 0 {
		r.State = "prepared"
		r.KernelReady = true
	}
	if all != nil {
		r.State = "recovery_required"
		r.Reason = "candidate_requires_attention"
		r.KernelReady = false
	}
	return r, all
}
