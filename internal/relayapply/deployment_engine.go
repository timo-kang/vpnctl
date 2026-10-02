// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"vpnctl/internal/relaycache"
)

type deploymentCache interface {
	Status() (relaycache.DeploymentReport, error)
	DeploymentJournal() ([]byte, error)
	SaveDeploymentJournal([]byte) error
}
type deploymentBackend interface {
	Check(context.Context, DeploymentEntry, bool) (bool, error)
	Step(context.Context, DeploymentEntry, string, string) error
	Down(context.Context, DeploymentEntry) error
	Remove(context.Context, DeploymentEntry) error
	Lease(context.Context, DeploymentEntry, time.Time, FreshApproval) (DeploymentLease, error)
	LeaseStatus(context.Context, DeploymentEntry) (DeploymentLease, error)
}
type DeploymentEngine struct {
	mu        sync.Mutex
	cache     deploymentCache
	journal   deploymentJournal
	backend   deploymentBackend
	unlock    func()
	uncertain bool
	closed    bool
}

func OpenDeployment(cache *relaycache.DeploymentStore) (*DeploymentEngine, error) {
	unlock, err := kernelLock()
	if err != nil {
		return nil, err
	}
	d, err := domain()
	if err != nil {
		unlock()
		return nil, err
	}
	e, err := openDeploymentEngine(cache, d, bootDeploymentKernel{deploymentKernel{kernel{run: command}}})
	if err != nil {
		unlock()
		return nil, err
	}
	e.unlock = unlock
	return e, nil
}
func openDeploymentEngine(cache deploymentCache, domain string, b deploymentBackend) (*DeploymentEngine, error) {
	r, err := cache.Status()
	if err != nil {
		return nil, err
	}
	e := &DeploymentEngine{cache: cache, backend: b, journal: deploymentJournal{Version: 1, Principal: r.PrincipalID, Relay: r.RelayID, Domain: domain, Entries: []DeploymentEntry{}}}
	raw, err := cache.DeploymentJournal()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return e, nil
	}
	var env deploymentEnvelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 2<<20 || d.Decode(&env) != nil || d.Decode(new(any)) != io.EOF || env.Digest != deploymentHash(env.Journal) {
		return nil, errors.New("deployment journal corrupt")
	}
	j := env.Journal
	if j.Version != 1 || j.Principal != r.PrincipalID || j.Relay != r.RelayID || j.Domain != domain || j.Entries == nil || len(j.Entries) > 8 {
		return nil, errors.New("deployment journal identity or kernel domain mismatch")
	}
	seen := map[string]bool{}
	for _, v := range j.Entries {
		if err := validateDeploymentEntry(v, j); err != nil {
			return nil, err
		}
		if seen[v.Endpoint] {
			return nil, errors.New("duplicate endpoint journal")
		}
		seen[v.Endpoint] = true
	}
	e.journal = j
	return e, nil
}
func (e *DeploymentEngine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.unlock != nil {
		e.unlock()
		e.unlock = nil
	}
}
func (e *DeploymentEngine) persist() error {
	if e.uncertain {
		return relaycache.ErrUncertain
	}
	b, err := json.Marshal(deploymentEnvelope{e.journal, deploymentHash(e.journal)})
	if err == nil {
		err = e.cache.SaveDeploymentJournal(b)
	}
	if err != nil {
		e.uncertain = true
	}
	return err
}
func (e *DeploymentEngine) result(state, reason string) DeploymentResult {
	r := DeploymentResult{SchemaVersion: 1, State: state, Reason: reason, RelayID: e.journal.Relay, UplinkHealth: "unknown", ExpiryEnforcement: "kernel_lease", Endpoints: []DeploymentEndpointResult{}}
	for _, v := range e.journal.Entries {
		r.Endpoints = append(r.Endpoints, DeploymentEndpointResult{EndpointID: v.Endpoint, Interface: v.Interface, Phase: v.Phase, Peers: len(v.Peers)})
		if v.LeaseVersion == 0 {
			r.ExpiryEnforcement = "legacy_on_command"
		} else if v.LeaseVersion < 3 {
			r.ExpiryEnforcement = "legacy_upgrade_required"
		}
	}
	return r
}
func (e *DeploymentEngine) index(endpoint string) int {
	for i, v := range e.journal.Entries {
		if v.Endpoint == endpoint {
			return i
		}
	}
	return -1
}

// Quiesce first, using the already durable ownership record. If recording the
// deletion fails, keep that record and leave the owned link down for recovery.
func (e *DeploymentEngine) remove(ctx context.Context, i int) error {
	v := e.journal.Entries[i]
	if err := e.backend.Down(ctx, v); err != nil {
		return err
	}
	e.journal.Entries[i].Phase = "releasing"
	if err := e.persist(); err != nil {
		return err
	}
	if err := e.backend.Remove(ctx, e.journal.Entries[i]); err != nil {
		return err
	}
	e.journal.Entries = append(e.journal.Entries[:i], e.journal.Entries[i+1:]...)
	return e.persist()
}

// No stale configuration survives a command that observes invalid approval.
// A valid revision that removes a peer/endpoint or changes the key similarly
// quiesces the old endpoint; only Apply with a matching local key can restore it.
func (e *DeploymentEngine) enforce(ctx context.Context) (relaycache.DeploymentReport, error) {
	r, readErr := e.cache.Status()
	var failures error
	for i := len(e.journal.Entries) - 1; i >= 0; i-- {
		v := e.journal.Entries[i]
		want, err := desiredDeployment(r, v.Endpoint, v.ListenPort)
		if readErr != nil || err != nil || !sameDeployment(v, want) {
			failures = errors.Join(failures, e.remove(ctx, i))
		}
	}
	return r, errors.Join(readErr, failures)
}
func (e *DeploymentEngine) begin() error {
	if e.closed {
		return errors.New("deployment engine closed")
	}
	if e.uncertain {
		return relaycache.ErrUncertain
	}
	return nil
}
func (e *DeploymentEngine) Apply(ctx context.Context, o DeploymentOptions) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	r, err := e.enforce(ctx)
	if err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	v, err := desiredDeployment(r, o.EndpointID, o.ListenPort)
	if err != nil {
		return e.result("blocked", "approval_unavailable"), err
	}
	if o.KeyGeneration != v.KeyGeneration {
		return e.result("blocked", "local_key_generation_mismatch"), errors.New("local relay key generation does not match approval")
	}
	key, err := deploymentKey(o.KeyFile, v.PublicKey)
	if err != nil {
		return e.result("blocked", "local_key_unavailable_or_mismatched"), err
	}
	if i := e.index(o.EndpointID); i >= 0 {
		old := e.journal.Entries[i]
		if old.Phase != "applied" {
			return e.result("blocked", "recovery_required"), ErrRecovery
		}
		if !sameDeployment(old, v) {
			return e.result("blocked", "release_previous_endpoint_first"), ErrConflict
		}
		return e.inspect(ctx)
	}
	if len(e.journal.Entries) >= 8 {
		return e.result("blocked", "endpoint_limit"), ErrConflict
	}
	v.Alias, v.Group, v.LinkIndex, err = token()
	if err != nil {
		return e.result("blocked", "owner_unavailable"), err
	}
	if err = validateDeploymentEntry(v, e.journal); err != nil {
		return e.result("blocked", "invalid_intent"), err
	}
	if _, err = e.backend.Check(ctx, v, true); err != nil {
		return e.result("blocked", "resource_conflict_or_unavailable"), err
	}
	e.journal.Entries = append(e.journal.Entries, v)
	if err = e.persist(); err != nil {
		return e.result("blocked", "journal_save_failed"), err
	}
	// Linux requires the link up before installing its unicast routes.
	for _, step := range []string{"guard", "link", "tag", "wg", "up", "routes"} {
		current, x := e.cache.Status()
		want, y := desiredDeployment(current, o.EndpointID, o.ListenPort)
		if x != nil || y != nil || !sameDeployment(want, v) || ctx.Err() != nil {
			err = errors.New("approval expired or changed during deployment")
			break
		}
		secret := ""
		if step == "wg" {
			secret = key
		}
		if err = e.backend.Step(ctx, v, step, secret); err != nil {
			err = fmt.Errorf("relay deployment step %s: %w", step, err)
			break
		}
	}
	if err == nil {
		var ready bool
		ready, err = e.backend.Check(ctx, v, false)
		if err == nil && !ready {
			err = ErrRecovery
		}
	}
	if err == nil {
		r, x := e.cache.Status()
		w, y := desiredDeployment(r, o.EndpointID, o.ListenPort)
		if x != nil || y != nil || !sameDeployment(v, w) || ctx.Err() != nil {
			err = errors.New("approval expired or changed before commit")
		} else {
			fresh, clockErr := ObserveApproval()
			if clockErr != nil {
				err = clockErr
			} else {
				_, err = e.backend.Lease(ctx, v, r.Deployment.ExpiresAt, fresh)
			}
		}
	}
	if err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), MaxDuration)
		defer stop()
		recovery := e.remove(cleanup, e.index(o.EndpointID))
		// Expiry while adding one endpoint also invalidates previously installed
		// endpoints; rolling back only the current attempt would leave peers up.
		if _, remaining := e.enforce(cleanup); recovery != nil || remaining != nil {
			return e.result("blocked", "recovery_required"), errors.Join(err, recovery, remaining)
		}
		return e.result("blocked", "apply_failed_rolled_back"), err
	}
	e.journal.Entries[e.index(o.EndpointID)].Phase = "applied"
	if err = e.persist(); err != nil {
		cleanup, stop := context.WithTimeout(context.Background(), MaxDuration)
		defer stop()
		return e.result("blocked", "journal_save_failed"), errors.Join(err, e.backend.Down(cleanup, v))
	}
	return e.inspect(ctx)
}
func (e *DeploymentEngine) inspect(ctx context.Context) (DeploymentResult, error) {
	return e.inspectWithCleanup(ctx, true)
}

func (e *DeploymentEngine) inspectWithCleanup(ctx context.Context, independentCleanup bool) (DeploymentResult, error) {
	r, err := e.enforce(ctx)
	if err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	if !r.ApprovalValid {
		return e.result("blocked", "approval_unavailable"), errors.New("relay approval unavailable; owned endpoints removed")
	}
	out := e.result("applied", "")
	out.KernelReady = len(e.journal.Entries) > 0
	if len(e.journal.Entries) == 0 {
		out.State = "empty"
	}
	for i, v := range e.journal.Entries {
		ready, x := e.backend.Check(ctx, v, false)
		lease, leaseErr := e.backend.LeaseStatus(ctx, v)
		out.Endpoints[i].Lease = &lease
		if leaseErr != nil || !lease.Active || r.Deployment == nil || lease.Deadline.After(r.Deployment.ExpiresAt) {
			ready = false
			x = errors.Join(x, leaseErr, errors.New("relay lease unavailable or expired"))
		}
		out.Endpoints[i].KernelReady = ready && x == nil && v.Phase == "applied"
		if !out.Endpoints[i].KernelReady {
			out.KernelReady = false
			err = errors.Join(err, ErrRecovery, x)
		}
	}
	// Kernel inventory may take several seconds. Recheck approval after it,
	// with a separate cleanup budget for CLI calls only. Supervision retains
	// its caller's deadline because the kernel independently expires traffic.
	before := deploymentHash(e.journal)
	cleanup, stop := ctx, func() {}
	if independentCleanup {
		cleanup, stop = context.WithTimeout(context.Background(), MaxDuration)
	}
	defer stop()
	latest, checkErr := e.enforce(cleanup)
	if checkErr != nil || !latest.ApprovalValid || before != deploymentHash(e.journal) {
		return e.result("blocked", "approval_changed_during_inspection"), errors.Join(err, checkErr, errors.New("relay approval changed during inspection"))
	}
	if err != nil {
		out.State = "blocked"
		out.Reason = "kernel_conflict_or_recovery_required"
	}
	return out, err
}

// Maintain renews only already applied, still approved resources. A fresh
// authenticated response is required to automatically rearm an expired lease.
func (e *DeploymentEngine) Maintain(ctx context.Context, authenticatedAt FreshApproval) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	r, err := e.enforce(ctx)
	// A foreign resource may prevent removing one obsolete endpoint. Keep
	// renewing independent, still-approved endpoints instead of starving the
	// whole relay. Never renew an obsolete entry left behind by failed cleanup.
	if err != nil {
		var statusErr error
		r, statusErr = e.cache.Status()
		if statusErr != nil || e.uncertain {
			return e.result("blocked", "approval_or_cleanup_failed"), errors.Join(err, statusErr)
		}
	}
	for _, v := range e.journal.Entries {
		want, approvalErr := desiredDeployment(r, v.Endpoint, v.ListenPort)
		if approvalErr != nil || !sameDeployment(v, want) {
			continue // enforce has already attempted to quiesce this entry.
		}
		ready, x := e.backend.Check(ctx, v, false)
		if x != nil || !ready || v.Phase != "applied" {
			err = errors.Join(err, ErrRecovery, x, e.backend.Down(ctx, v))
			continue
		}
		if !r.ApprovalValid || r.Deployment == nil {
			err = errors.Join(err, ErrRecovery)
			continue
		}
		_, x = e.backend.Lease(ctx, v, r.Deployment.ExpiresAt, authenticatedAt)
		if x != nil && !errors.Is(x, ErrLeaseExpired) {
			x = errors.Join(x, e.backend.Down(ctx, v))
		}
		err = errors.Join(err, x)
	}
	if err != nil {
		return e.result("blocked", "lease_renewal_failed"), err
	}
	// The supervisor already has an independent kernel expiry guard. Keep
	// its cycle budget instead of inheriting a CLI's 60s cleanup extension.
	return e.inspectWithCleanup(ctx, false)
}
func (e *DeploymentEngine) Inspect(ctx context.Context) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	return e.inspect(ctx)
}
func (e *DeploymentEngine) Release(ctx context.Context, endpoint string) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	// Check all endpoints so release of one cannot overlook known revocation.
	if _, err := e.enforce(ctx); err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	if i := e.index(endpoint); i >= 0 {
		if err := e.remove(ctx, i); err != nil {
			return e.result("blocked", "recovery_required"), err
		}
	}
	cleanup, stop := context.WithTimeout(context.Background(), MaxDuration)
	defer stop()
	if _, err := e.enforce(cleanup); err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	return e.result("released", ""), nil
}
func (e *DeploymentEngine) Recover(ctx context.Context) (DeploymentResult, error) {
	if !e.mu.TryLock() {
		return DeploymentResult{}, relaycache.ErrBusy
	}
	defer e.mu.Unlock()
	if err := e.begin(); err != nil {
		return e.result("blocked", "reopen_required"), err
	}
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	if _, err := e.enforce(ctx); err != nil {
		return e.result("blocked", "approval_or_cleanup_failed"), err
	}
	for i := len(e.journal.Entries) - 1; i >= 0; i-- {
		if e.journal.Entries[i].Phase != "applied" {
			if err := e.remove(ctx, i); err != nil {
				return e.result("blocked", "recovery_required"), err
			}
		}
	}
	return e.inspect(ctx)
}
