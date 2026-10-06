// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

const MaxTargetProbeDuration = 20 * time.Second

type TargetObservation = relayobserve.TargetObservation
type TargetReport = relayobserve.TargetReport

type targetProof struct {
	duration  time.Duration
	handshake int64
	rx, tx    uint64
}

// ObserveTarget holds the same cache and namespace locks as prepare. No route,
// peer, interface or policy-routing rule is changed. Protected candidates cooperatively renew
// their leases between bounded probes while holding the shared lock. Each TCP socket pins both the approved
// candidate interface and its inner source; it cannot use a healthy neighbour.
func (e *Engine) ObserveTarget(parent context.Context, targetID, controller string, timeout time.Duration) (TargetReport, error) {
	return e.observeTarget(parent, targetID, controller, timeout, e.candidateProbe())
}

func (e *Engine) candidateProbe() func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
	if e.probe != nil {
		return e.probe
	}
	return kernel{run: command}.probeTarget
}

func (e *Engine) observeTarget(parent context.Context, targetID, controller string, timeout time.Duration, probe func(context.Context, Entry, relaycatalog.Target) (targetProof, error)) (out TargetReport, err error) {
	parent, recorder := relayobserve.Start(parent)
	defer func() { out.Diagnostics = recorder.Snapshot() }()
	out = TargetReport{SchemaVersion: 1, TargetID: targetID, StartedAt: time.Now(), Paths: []TargetObservation{}}
	defer func() {
		out.ObservedAt = time.Now()
		boot, bootErr := leaseBootTime()
		out.BootTime = boot
		if bootErr != nil || err != nil || parent.Err() != nil {
			out.Valid = false
			if out.Reason == "" {
				out.Reason = "observation_unavailable"
			}
			err = errors.Join(err, bootErr, parent.Err())
		}
	}()
	if targetID == "" || timeout <= 0 || timeout > 2*time.Second {
		return out, errors.New("target ID and probe timeout in (0,2s] required")
	}
	if e.uncertain {
		return out, errors.New("reopen uncertain journal before observation")
	}
	ctx, cancel := context.WithTimeout(parent, MaxTargetProbeDuration)
	defer cancel()
	report, err := e.cache.Status()
	if err != nil {
		return out, err
	}
	out.ControllerID, out.NodeID, out.Generation = report.ControllerID, report.NodeID, report.ObservedGeneration
	if report.Catalog == nil || report.Validity != "valid" || report.BlockedReason != "" || report.Refresh.Result == "in_progress" {
		out.Reason = "approval_unavailable"
		return out, nil
	}
	view := report.Catalog
	if controller != "" && controller != view.ControllerID {
		out.Reason = "controller_identity_mismatch"
		return out, nil
	}
	out.ApprovalUntil = view.ExpiresAt
	var target relaycatalog.Target
	for _, t := range view.Spec.Targets {
		if t.ID == targetID {
			target = t
		}
	}
	if target.ID == "" || view.Validate(out.NodeID, time.Now()) != nil {
		out.Reason = "target_or_catalog_invalid"
		return out, nil
	}
	startedBoot, err := leaseBootTime()
	if err != nil {
		return out, err
	}
	remaining := time.Until(view.ExpiresAt)
	for _, path := range view.Spec.Paths {
		if !slices.Contains(path.TargetIDs, targetID) {
			continue
		}
		if e.hasLeases() {
			// Long batches must not exclude the supervisor for an entire 20s
			// without lease maintenance. This cannot rearm from cached evidence.
			_, _ = e.MaintainLeases(ctx)
		}
		observation := TargetObservation{PathID: path.ID, RelayID: path.RelayID, UnderlayID: path.UnderlayID, Priority: path.Priority, Cost: path.Cost, State: "unknown", ObservedAt: time.Now()}
		switch {
		case path.Disabled:
			observation.State, observation.Reason = "excluded", "disabled"
		case path.Drain:
			observation.State, observation.Reason = "excluded", "draining"
		default:
			i := e.index(path.ID)
			if i < 0 {
				observation.Reason = "candidate_not_prepared"
			} else {
				observation = e.observePrepared(ctx, e.journal.Entries[i], target, timeout, observation, probe)
			}
		}
		out.Paths = append(out.Paths, observation)
	}
	// Reject the complete batch on expiry, clock discontinuity or cancellation;
	// earlier successes must not escape a batch whose authority has expired.
	endBoot, bootErr := leaseBootTime()
	after, statusErr := e.cache.Status()
	if bootErr != nil || statusErr != nil {
		return out, errors.Join(bootErr, statusErr)
	}
	if ctx.Err() != nil {
		out.Reason = "observation_deadline"
		return out, ctx.Err()
	}
	if !after.UsableCache || after.Validity != "valid" || after.ObservedGeneration != out.Generation || !time.Now().Before(view.ExpiresAt) || time.Since(out.StartedAt) >= remaining || endBoot < startedBoot || endBoot-startedBoot >= remaining {
		out.Reason = "approval_expired_or_changed"
		return out, nil
	}
	out.Valid = true
	return out, nil
}

func (e *Engine) observePrepared(ctx context.Context, entry Entry, target relaycatalog.Target, timeout time.Duration, out TargetObservation, probe func(context.Context, Entry, relaycatalog.Target) (targetProof, error)) TargetObservation {
	return e.observePreparedGated(ctx, entry, target, timeout, out, probe, nil)
}

// Only the socket proof may overlap. Approval/cache, inventory, kernel checks
// and any fail-closed lease mutation use the shared, context-bounded gate.
func (e *Engine) observePreparedGated(ctx context.Context, entry Entry, target relaycatalog.Target, timeout time.Duration, out TargetObservation, probe func(context.Context, Entry, relaycatalog.Target) (targetProof, error), gate chan struct{}) TargetObservation {
	if entry.LeaseVersion != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	out.ObservedAt = time.Time{}
	finish := func(state, reason string) TargetObservation {
		out.State, out.Reason = state, reason
		if out.ObservedAt.IsZero() {
			out.ObservedAt = time.Now()
		}
		return out
	}
	ctx, finishStage, stageErr := observationStage(ctx, "precheck", gate)
	defer func() { finishStage() }()
	if stageErr != nil {
		return finish("unknown", "observation_deadline")
	}
	if !entry.ProbeRouting {
		return finish("unknown", "probe_routing_not_prepared")
	}
	if entry.Phase != "prepared" {
		return finish("unknown", "pending_journal")
	}
	if e.stillApproved(entry) != nil {
		return finish("unknown", "approval_expired_or_changed")
	}
	if _, err := e.checkLease(ctx, entry); err != nil {
		return finish("unknown", "lease_inactive")
	}
	// Bind evidence to the installed resource generation, not a reusable path ID.
	b, _ := json.Marshal(entry)
	sum := sha256.Sum256(b)
	out.Fingerprint = hex.EncodeToString(sum[:])
	ready, err := e.backend.Check(ctx, entry, false)
	if err != nil || !ready {
		return finish("unknown", "kernel_conflict_or_unavailable")
	}
	if err = inventoryMatches(ctx, entry, e.underlays, e.collector); err != nil {
		return finish("unknown", "inventory_changed")
	}
	finishStage()
	finishStage = func() {}
	probeCtx, endProbe := relayobserve.Phase(ctx, "probe")
	probeCtx, cancel := context.WithTimeout(probeCtx, timeout)
	proof, probeErr := probe(probeCtx, entry, target)
	out.ObservedAt = time.Now()
	cancel()
	endProbe()
	ctx, finishStage, stageErr = observationStage(ctx, "postcheck", gate)
	if stageErr != nil {
		return finish("unknown", "observation_deadline")
	}
	// A successful TCP connect cannot override a concurrent ownership or
	// inventory change. Even a network failure is attributable only after checks.
	ready, err = e.backend.Check(ctx, entry, false)
	if err != nil || !ready {
		return finish("unknown", "kernel_changed_during_probe")
	}
	if inventoryMatches(ctx, entry, e.underlays, e.collector) != nil {
		return finish("unknown", "inventory_changed")
	}
	if e.stillApproved(entry) != nil {
		return finish("unknown", "approval_expired_or_changed")
	}
	if ctx.Err() != nil {
		return finish("unknown", "observation_deadline")
	}
	if _, err := e.checkLease(ctx, entry); err != nil {
		return finish("unknown", "lease_expired_during_probe")
	}
	if probeErr != nil {
		var failure *targetConnectError
		if errors.As(probeErr, &failure) {
			return finish("unreachable", failure.reason)
		}
		return finish("unknown", "probe_evidence_unavailable")
	}
	out.ConnectTime, out.Handshake, out.RXDelta, out.TXDelta = proof.duration, proof.handshake, proof.rx, proof.tx
	return finish("reachable", "tcp_connect_verified")
}

type targetConnectError struct{ reason string }

func (e *targetConnectError) Error() string { return e.reason }

type targetCounters struct {
	handshake int64
	rx, tx    uint64
}

func (k kernel) targetCounters(ctx context.Context, entry Entry) (targetCounters, error) {
	var out targetCounters
	for _, field := range []string{"latest-handshakes", "transfer"} {
		b, err := k.run(ctx, "", "wg", "show", entry.Candidate.Pin.WGInterface, field)
		if err != nil {
			return out, err
		}
		f := strings.Fields(string(b))
		want := 2
		if field == "transfer" {
			want = 3
		}
		if len(f) != want || f[0] != entry.Candidate.RelayPublicKey {
			return out, errors.New("invalid candidate counters")
		}
		if field == "latest-handshakes" {
			out.handshake, err = strconv.ParseInt(f[1], 10, 64)
			if err != nil || out.handshake < 0 {
				return out, errors.New("invalid handshake")
			}
		} else {
			out.rx, err = strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return out, errors.New("invalid receive counter")
			}
			out.tx, err = strconv.ParseUint(f[2], 10, 64)
			if err != nil {
				return out, errors.New("invalid transmit counter")
			}
		}
	}
	return out, nil
}

func (k kernel) probeTarget(ctx context.Context, entry Entry, target relaycatalog.Target) (targetProof, error) {
	if err := k.targetRoute(ctx, entry, target); err != nil {
		return targetProof{}, err
	}
	before, err := k.targetCounters(ctx, entry)
	if err != nil {
		return targetProof{}, err
	}
	began := time.Now()
	conn, err := dialTarget(ctx, entry, target)
	if err != nil {
		return targetProof{}, classifyTargetConnect(err)
	}
	defer conn.Close()
	duration := time.Since(began)
	if err := k.targetRoute(ctx, entry, target); err != nil {
		return targetProof{}, err
	}
	after, err := k.targetCounters(ctx, entry)
	if err != nil {
		return targetProof{}, err
	}
	if after.handshake <= 0 || after.rx <= before.rx || after.tx <= before.tx {
		return targetProof{}, errors.New("TCP success without candidate WG transfer evidence")
	}
	return targetProof{duration, after.handshake, after.rx - before.rx, after.tx - before.tx}, nil
}

func dialTarget(ctx context.Context, entry Entry, target relaycatalog.Target) (net.Conn, error) {
	source, err := netip.ParsePrefix(entry.Candidate.InnerAddress)
	if err != nil || !source.Addr().Is4() || source.Bits() != 32 || entry.Candidate.Pin == nil {
		return nil, errors.New("invalid candidate source")
	}
	address, err := netip.ParseAddr(target.ProbeAddress)
	if err != nil || !address.Is4() || target.Protocol != "tcp" || target.Port == 0 {
		return nil, errors.New("invalid TCP target")
	}
	contained := false
	for _, prefix := range target.Prefixes {
		p, e := netip.ParsePrefix(prefix)
		contained = contained || e == nil && p.Contains(address)
	}
	if !contained {
		return nil, errors.New("target outside approved prefixes")
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(source.Addr().AsSlice())}, Control: func(_, _ string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, entry.Candidate.Pin.WGInterface)
		})
		return errors.Join(err, bindErr)
	}}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(address.String(), fmt.Sprint(target.Port)))
}

func classifyTargetConnect(err error) error {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return &targetConnectError{"timeout"}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return &targetConnectError{"timeout"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return &targetConnectError{"refused"}
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return &targetConnectError{"unreachable"}
	default:
		return err // permission, cancellation, resource exhaustion are unknown
	}
}

// In particular, reject a local target or an unexpected gateway. A local TCP
// service plus unrelated WG traffic must not be attributed to this relay.
func (k kernel) targetRoute(ctx context.Context, entry Entry, target relaycatalog.Target) error {
	source := strings.TrimSuffix(entry.Candidate.InnerAddress, "/32")
	rows, err := k.list(ctx, "-j", "-N", "-4", "route", "get", target.ProbeAddress, "from", source, "oif", entry.Candidate.Pin.WGInterface)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return errors.New("ambiguous target route")
	}
	r := rows[0]
	if str(r, "dev") != entry.Candidate.Pin.WGInterface || str(r, "from") != source || str(r, "gateway") != "" || str(r, "type") != "" && str(r, "type") != "unicast" && str(r, "type") != "1" {
		return errors.New("target route does not use approved candidate")
	}
	return nil
}

func observationStage(ctx context.Context, phase string, gate chan struct{}) (context.Context, func(), error) {
	ctx, done := relayobserve.Phase(ctx, phase)
	if gate == nil {
		return ctx, done, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx, done, ctx.Err()
	case gate <- struct{}{}:
		return ctx, func() { <-gate; done() }, ctx.Err()
	}
}
