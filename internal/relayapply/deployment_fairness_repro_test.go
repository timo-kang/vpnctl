// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// Inject one slow durable write at the exact healthy-endpoint boundary shown
// in final44 CI: ep1's step 4 has been recorded InFlight. The real 750ms context
// expires; this fake does not manufacture a DeadlineExceeded return value or
// change the deadline, journal bytes, host clock, or kernel state.
type fairnessReproDelay struct {
	delayed  bool
	oldOwner string
}

type fairnessReproSave struct {
	deploymentCache
	fault *fairnessReproDelay
}

func (c *fairnessReproSave) SaveDeploymentJournal(b []byte) error {
	var env deploymentEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	delay := false
	for _, p := range env.Journal.Installations {
		delay = delay || !c.fault.delayed && p.Endpoint == "ep1" && p.Step == 4 && p.InFlight
	}
	if err := c.deploymentCache.SaveDeploymentJournal(b); err != nil {
		return err
	}
	if delay {
		c.fault.delayed = true
		for _, entry := range env.Journal.Entries {
			if entry.Endpoint == "ep1" {
				c.fault.oldOwner = entry.Alias
			}
		}
		time.Sleep(DeploymentRebuildDuration + 50*time.Millisecond)
	}
	return nil
}

// The original fairness test aborts immediately on this ordinary cycle timeout.
// This independent control keeps its 24 progress units per attempt and repeated
// restart/backoff-expiry pressure on broken ep0, but follows the existing
// conservative recovery path after exactly one injected healthy-endpoint timeout.
// It proves this timeout can coexist with preserved fairness and closed leases;
// it does not identify which host operation delayed the historical CI runner.
func TestRelayInstallationFairnessRecoversOneSlowDurableSave(t *testing.T) {
	e, k, cache, dir, key := installationPair(t)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if r, err := e.RebuildInstallations(ctx, installationWitness(t)); err == nil || r.Reason != "local_key_unavailable_or_mismatched" {
		t.Fatalf("missing-key setup changed: reason=%s err=%v", r.Reason, err)
	}
	failed := e.journal.Installations[e.installationIndex("ep0")]
	if failed.Failures != 1 || failed.RetryBootNS == 0 || e.journal.InstallCursor != "ep0" || len(k.objects) != 0 {
		t.Fatal("failed endpoint did not durably yield before healthy work")
	}
	e, cache = reopenDeployment(t, e, cache, dir)
	if e.journal.InstallCursor != "ep0" || e.journal.Installations[e.installationIndex("ep0")].RetryBootNS != failed.RetryBootNS {
		t.Fatal("restart lost failed-endpoint cursor or backoff")
	}
	fault := &fairnessReproDelay{}
	removedOld := false
	e.backend = &installationRecoveryObserver{deploymentBackend: e.backend, removing: func(entry DeploymentEntry) {
		if entry.Endpoint == "ep1" && entry.Alias == fault.oldOwner {
			boot, err := leaseBootTime()
			p := e.journal.Installations[e.installationIndex("ep1")]
			if err != nil || uint64(boot) < p.RetryBootNS {
				t.Fatal("interrupted owner cleanup ignored retry backoff", err)
			}
			removedOld = true
		}
	}}
	interruptions := 0
	for progress := 0; progress < 24; {
		if err := ctx.Err(); err != nil {
			t.Fatal("fairness recovery exceeded overall bound", err)
		}
		// Retain the real healthy-endpoint backoff. Only ep0 gets the original
		// test's explicit elapsed-backoff model, creating repeated retry pressure.
		if err := waitInstallationTestRetry(ctx, e, "ep1"); err != nil {
			t.Fatal(err)
		}
		e.journal.Installations[e.installationIndex("ep0")].RetryBootNS = 0
		if err := e.persist(); err != nil {
			t.Fatal(err)
		}
		e, cache = reopenDeployment(t, e, cache, dir)
		e.cache = &fairnessReproSave{deploymentCache: e.cache, fault: fault}
		r, err := e.RebuildInstallations(ctx, installationWitness(t))
		if invalid := installationTestClosed(ctx, e); invalid != nil {
			t.Fatal("installation recovery violated closed-lease or journal invariant", invalid)
		}
		if _, exists := k.objects["ep0"]; exists {
			t.Fatal("missing-key endpoint installed")
		}
		if err != nil && r.Reason != "local_key_unavailable_or_mismatched" {
			if e.uncertain || ctx.Err() != nil || !installationDeadlineOnly(err) || r.Reason != "installation_step_interrupted" {
				t.Fatalf("unexpected failure: uncertain=%t reason=%s err=%v", e.uncertain, r.Reason, err)
			}
			interruptions++
			if interruptions > 1 || !fault.delayed {
				t.Fatal("exceeded the single injected deadline recovery allowance")
			}
			p := e.journal.Installations[e.installationIndex("ep1")]
			if p.Step != 4 || !p.InFlight || p.Failures != 1 || p.RetryBootNS == 0 || e.journal.InstallCursor != "ep1" {
				t.Fatal("deadline lost durable recovery position or fairness cursor")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("slow durable save did not expire the real cycle context")
			}
			t.Logf("injected timeout preserved endpoint=ep1 step=%d in_flight=%t failures=%d cursor=%s closed_lease=true", p.Step, p.InFlight, p.Failures, e.journal.InstallCursor)
			progress = 0 // Exactly one fresh 24-unit attempt after cleanup is needed.
			continue
		}
		progress++
		if i := e.index("ep1"); i >= 0 && e.journal.Entries[i].Phase == "applied" {
			if !fault.delayed || interruptions != 1 || !removedOld || e.journal.Entries[i].Alias == fault.oldOwner {
				t.Fatal("healthy convergence skipped the interrupted-owner recovery")
			}
			t.Logf("healthy endpoint converged after interruption with %d/24 progress units; missing-key endpoint remained absent", progress)
			return
		}
	}
	t.Fatal("healthy endpoint failed the unchanged 24-unit convergence bound")
}
