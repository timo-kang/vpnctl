// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"vpnctl/internal/relayguard"
)

// Starting a timeout and granting traffic MUST be separate transactions. The
// second transaction only references an already counting, never renewed set.
// A delayed grant therefore cannot restart its timer, even after clock rollback.
// Names are never reused: a queued grant must not attach to a later generation.
func leaseSetName() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "lease_" + hex.EncodeToString(b), nil
}

func validLeaseSet(s string) bool {
	if len(s) != 38 || !strings.HasPrefix(s, "lease_") {
		return false
	}
	b, err := hex.DecodeString(s[6:])
	return err == nil && hex.EncodeToString(b) == s[6:]
}

func stagedLeaseRules(e DeploymentEntry, deadline time.Time, set string) string {
	return strings.ReplaceAll(leaseRules(e, deadline), "@alive", "@"+set)
}

func stagedLeaseSet(e DeploymentEntry, set string) string {
	return fmt.Sprintf("create set inet %s %s { type iface_index; flags timeout; timeout %ds; size 1; comment %q; }\n", leaseTable(e), set, int(DeploymentLeaseDuration.Seconds()), e.Alias)
}

// Validate both the selected timer and at most one unselected preparation left
// by a crash. Normalize only their unique names and owner comments, then reuse
// the strict v1 rule/property validator. An extra rule or foreign set is never
// accepted as a harmless preparation.
func validateStagedLease(rows []object, e DeploymentEntry) (DeploymentLease, error) {
	state := DeploymentLease{}
	sets := map[string]object{}
	other := []object{}
	for _, row := range rows {
		if len(row) != 1 {
			return state, ErrConflict
		}
		if raw, ok := row["set"]; ok {
			x, ok := raw.(map[string]any)
			if !ok {
				return state, ErrConflict
			}
			name, ok := x["name"].(string)
			if !ok || !validLeaseSet(name) || sets[name] != nil || x["comment"] != e.Alias {
				return state, ErrConflict
			}
			sets[name] = x
			continue
		}
		if raw, ok := row["rule"]; ok {
			x, _ := raw.(map[string]any)
			exprs, _ := x["expr"].([]any)
			for _, raw := range exprs {
				expr, _ := raw.(map[string]any)
				m, _ := expr["match"].(map[string]any)
				ref, _ := m["right"].(string)
				if strings.HasPrefix(ref, "@") {
					name := strings.TrimPrefix(ref, "@")
					if !validLeaseSet(name) || state.set != "" && state.set != name {
						return state, ErrConflict
					}
					state.set = name
					m["right"] = "@alive"
				}
			}
		}
		other = append(other, row)
	}
	if len(sets) < 1 || len(sets) > 2 || sets[state.set] == nil {
		return state, ErrConflict
	}
	// Each possible timer must have precisely the allowed single-element shape.
	// Reusing the complete validator also rejects altered hooks, rules and owners.
	for name, set := range sets {
		set["name"] = "alive"
		delete(set, "comment")
		candidate := []object{}
		for _, row := range other {
			candidate = append(candidate, row)
			if _, ok := row["table"]; ok {
				candidate = append(candidate, object{"set": map[string]any(set)})
			}
		}
		checked, err := validateLease(candidate, e)
		if err != nil {
			return DeploymentLease{}, fmt.Errorf("timer %s: %w", name, err)
		}
		if name == state.set {
			state.Active, state.Deadline = checked.Active, checked.Deadline
		} else {
			state.staged = append(state.staged, name)
		}
	}
	return state, nil
}

func (k deploymentKernel) stagedLeaseCreate(ctx context.Context, e DeploymentEntry) error {
	if _, exists, err := k.leaseRead(ctx, e); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	if err := k.noFlowtables(ctx); err != nil {
		return err
	}
	set, err := leaseSetName()
	if err != nil {
		return err
	}
	script := fmt.Sprintf("create table inet %s { comment %q; }\n", leaseTable(e), e.Alias) + stagedLeaseSet(e, set)
	for _, hook := range []string{"input", "forward", "output"} {
		script += fmt.Sprintf("add chain inet %s %s { type filter hook %s priority -300; policy accept; }\n", leaseTable(e), hook, hook)
	}
	script += stagedLeaseRules(e, time.Unix(1, 0), set)
	_, err = k.run(ctx, script, "nft", "-f", "/dev/stdin")
	return err
}

const leasePrepareBudget = time.Second
const leaseTimerMargin = 100 * time.Millisecond

func (k deploymentKernel) stagedLease(ctx context.Context, e DeploymentEntry, expiry time.Time, authenticated FreshApproval, boot *relayguard.State) (DeploymentLease, error) {
	return k.stagedLeaseBounded(ctx, e, expiry, authenticated, boot, 0)
}

func (k deploymentKernel) stagedLeaseBounded(ctx context.Context, e DeploymentEntry, expiry time.Time, authenticated FreshApproval, boot *relayguard.State, approvalBootNS uint64) (DeploymentLease, error) {
	state, exists, err := k.leaseRead(ctx, e)
	if err != nil {
		return state, err
	}
	if !exists {
		return state, errors.New("relay lease missing")
	}
	if err = k.noFlowtables(ctx); err != nil {
		return state, err
	}
	started := time.Now()
	bootStarted, err := leaseBootTime()
	if err != nil {
		return state, err
	}
	if boot != nil {
		state.Active = state.Active && boot.Active
	}
	rearmed := !state.Active
	authenticatedAt := authenticated.At
	deadline, err := leaseDeadline(state.Active, expiry, authenticatedAt, started.UTC())
	if err != nil {
		return state, err
	}
	remaining := deadline.Sub(started)
	if approvalBootNS != 0 {
		if uint64(bootStarted) >= approvalBootNS {
			return state, ErrLeaseExpired
		}
		remaining = min(remaining, time.Duration(approvalBootNS-uint64(bootStarted)))
	}
	if !state.Active {
		// Fresh responses carry a process-local monotonic timestamp. A small
		// wall rollback must not turn an old response into a new rearm window.
		age := started.Sub(authenticatedAt)
		if age < 0 || age >= DeploymentRearmWindow {
			return state, ErrLeaseExpired
		}
		remaining = min(remaining, DeploymentRearmWindow-age)
		if boot != nil {
			if authenticated.BootNS == 0 || uint64(bootStarted) < authenticated.BootNS || uint64(bootStarted)-authenticated.BootNS >= uint64(DeploymentRearmWindow) {
				return state, ErrLeaseExpired
			}
			remaining = min(remaining, DeploymentRearmWindow-time.Duration(uint64(bootStarted)-authenticated.BootNS))
		}
	}
	timerMS := (remaining - leasePrepareBudget).Milliseconds()
	if timerMS < 1 || timerMS > DeploymentLeaseDuration.Milliseconds() {
		return state, ErrLeaseExpired
	}
	set, err := leaseSetName()
	if err != nil {
		return state, err
	}
	table := leaseTable(e)
	script := ""
	for _, abandoned := range state.staged {
		script += fmt.Sprintf("delete set inet %s %s\n", table, abandoned)
	}
	script += stagedLeaseSet(e, set)
	script += fmt.Sprintf("add element inet %s %s { %d timeout %dms }\n", table, set, e.LinkIndex, timerMS)
	if _, err = k.run(ctx, script, "nft", "-f", "/dev/stdin"); err != nil {
		return state, err
	}
	// A delayed preparation is harmless until selected. Bound its LATEST expiry
	// using the ACK time plus its full timeout, with a kernel tick safety margin.
	// CLOCK_BOOTTIME includes guest suspend; realtime rollback cannot hide delay.
	bootFinished, err := leaseBootTime()
	if err != nil {
		return state, err
	}
	elapsed := max(time.Since(started), bootFinished-bootStarted)
	if ctx.Err() != nil {
		return state, ctx.Err()
	}
	if bootFinished < bootStarted || elapsed+time.Duration(timerMS)*time.Millisecond+leaseTimerMargin > remaining || !time.Now().Before(deadline) {
		return state, ErrLeaseExpired
	}
	if boot != nil {
		freshUntil := uint64(0)
		if authenticated.BootNS != 0 {
			freshUntil = authenticated.BootNS + uint64(DeploymentRearmWindow)
		}
		_, err := relayguard.Update(ctx, guardOwner(e), boot.Generation, uint64(bootStarted)+uint64(remaining), freshUntil)
		if errors.Is(err, relayguard.ErrExpired) {
			return state, ErrLeaseExpired
		}
		if err != nil {
			return state, err
		}
	}
	// Continuation is conditional on the old timer still existing in the kernel
	// transaction. Never silently convert a failed continuation to a fresh grant.
	script = ""
	if state.Active {
		script += fmt.Sprintf("delete element inet %s %s { %d }\n", table, state.set, e.LinkIndex)
	}
	for _, hook := range []string{"input", "forward", "output"} {
		script += fmt.Sprintf("flush chain inet %s %s\n", table, hook)
	}
	script += stagedLeaseRules(e, deadline, set)
	script += fmt.Sprintf("delete set inet %s %s\n", table, state.set)
	if _, err = k.run(ctx, script, "nft", "-f", "/dev/stdin"); err != nil {
		// Expiry during conditional continuation is normal. Inventory conflicts
		// remain errors and may require quiescing the owned link.
		latest, present, readErr := k.leaseRead(ctx, e)
		if readErr == nil && present && !latest.Active && latest.set == state.set {
			return latest, ErrLeaseExpired
		}
		return state, errors.Join(err, readErr)
	}
	state, exists, err = k.leaseRead(ctx, e)
	if err == nil {
		if !exists || state.set != set || !state.Deadline.Equal(deadline) || len(state.staged) != 0 {
			err = errors.New("relay lease readback incomplete")
		} else if !state.Active {
			err = ErrLeaseExpired
		}
	}
	state.rearmed = rearmed && err == nil && state.Active
	return state, err
}
