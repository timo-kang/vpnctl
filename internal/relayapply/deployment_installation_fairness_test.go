// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
)

func installationPair(t *testing.T) (*DeploymentEngine, *deploymentFake, *relaycache.DeploymentStore, string, string) {
	t.Helper()
	e, k, c, _, o, dir := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	firstKey := o.KeyFile
	key, err := os.ReadFile(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	o.EndpointID, o.ListenPort, o.KeyFile = "ep1", 51821, filepath.Join(filepath.Dir(firstKey), "healthy.key")
	if err := os.WriteFile(o.KeyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	return e, k, c, dir, firstKey
}

func breakInstallationConsent(t *testing.T, dir string, unsafe bool) {
	t.Helper()
	marker := filepath.Join(dir, fmt.Sprintf("install-%x", sha256.Sum256([]byte("ep0"))))
	var err error
	if unsafe {
		err = os.Chmod(marker, 0644)
	} else {
		err = os.WriteFile(marker, []byte("invalid revision"), 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRelayInstallationFailureDoesNotStarveOtherEndpoint(t *testing.T) {
	for _, mode := range []string{"malformed-consent", "unsafe-consent", "missing-key", "slow-save"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c, dir, key := installationPair(t)
			if mode == "missing-key" || mode == "slow-save" {
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			} else {
				breakInstallationConsent(t, dir, mode == "unsafe-consent")
			}
			if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err == nil {
				t.Fatal("endpoint failure was hidden")
			}
			p := e.journal.Installations[0]
			if p.Failures != 1 || p.RetryBootNS == 0 || e.journal.InstallCursor != "ep0" || len(k.objects) != 0 {
				t.Fatal("failed endpoint did not durably yield with backoff", e.installationStatus())
			}
			e, c = reopenDeployment(t, e, c, dir)
			if e.journal.InstallCursor != "ep0" || e.journal.Installations[0].RetryBootNS != p.RetryBootNS {
				t.Fatal("restart lost failed endpoint cursor or backoff")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			deadlineRecoveries := 0
			fault := &fairnessReproDelay{}
			for n := 0; n < 24; n++ {
				if err := waitInstallationTestRetry(ctx, e, "ep1"); err != nil {
					t.Fatal(err)
				}
				// Emulate a slow next cycle after the retry deadline, without
				// changing the host clock. Cursor fairness must survive both
				// elapsed backoff and a process restart between every unit.
				e.journal.Installations[0].RetryBootNS = 0
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				e, c = reopenDeployment(t, e, c, dir)
				if mode == "slow-save" {
					e.cache = &fairnessReproSave{deploymentCache: e.cache, fault: fault}
				}
				r, err := e.RebuildInstallations(ctx, installationWitness(t))
				if invalid := installationTestClosed(ctx, e); invalid != nil || e.uncertain {
					t.Fatal("installation violated closed-lease or journal invariant", invalid, err)
				}
				if err != nil && r.Reason != "installation_consent_unavailable" && r.Reason != "local_key_unavailable_or_mismatched" {
					// A real fsync can exceed the unchanged production quantum.
					// Permit only bounded, certain deadline recovery, as in
					// awaitInstallationReady; all other failures stay fatal.
					deadlineRecoveries++
					if ctx.Err() != nil || !installationDeadlineOnly(err) || deadlineRecoveries > 3 {
						t.Fatal(r, err)
					}
					n = -1 // Cleanup can require a fresh 24-unit attempt.
				}
				if _, exists := k.objects["ep0"]; exists {
					t.Fatal("failed endpoint installed")
				}
				if k.objects["ep1"].lease.Active {
					t.Fatal("rebuilding opened healthy endpoint's lease")
				}
				if i := e.index("ep1"); i >= 0 && e.journal.Entries[i].Phase == "applied" {
					if mode == "slow-save" && (!fault.delayed || deadlineRecoveries == 0) {
						t.Fatal("slow durable save did not exercise deadline recovery")
					}
					return
				}
			}
			t.Fatal("independent healthy installation starved", e.installationStatus())
		})
	}
}

func TestRelayInstallationConsentFailureJournalIsFailClosed(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("after%v", after), func(t *testing.T) {
			e, k, c, dir, _ := installationPair(t)
			breakInstallationConsent(t, dir, false)
			e.cache = &failingDeploymentCache{deploymentCache: e.cache, failAt: 1, after: after}
			if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err == nil || !e.uncertain {
				t.Fatal("failed cursor persistence did not close engine", err)
			}
			for n := 0; n < 10; n++ {
				r, err := e.RebuildInstallations(context.Background(), installationWitness(t))
				if err == nil || r.Reason != "reopen_required" || len(k.objects) != 0 {
					t.Fatal("uncertain journal allowed installation", r, err)
				}
			}
			e, c = reopenDeployment(t, e, c, dir)
			if after {
				if e.journal.InstallCursor != "ep0" || e.journal.Installations[0].Failures != 1 {
					t.Fatal("committed failure cursor was lost")
				}
			} else {
				if e.journal.InstallCursor != "" || e.journal.Installations[0].Failures != 0 {
					t.Fatal("uncommitted failure cursor survived")
				}
				if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err == nil {
					t.Fatal("corrupt consent accepted after restart")
				}
			}
			if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil || e.index("ep1") < 0 {
				t.Fatal("healthy endpoint could not resume after durable reopen", err)
			}
		})
	}
}

func TestRelayInstallationRevokedCleanupDoesNotStarveOtherEndpoint(t *testing.T) {
	e, k, c, _, o, dir := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	installationReady(t, e)
	o.EndpointID, o.ListenPort = "ep1", 51821
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeInstallation("ep0"); err != nil {
		t.Fatal(err)
	}
	e.backend = &failedInstallationDown{deploymentBackend: e.backend}
	for n := 0; n < 24; n++ {
		e.journal.Installations[0].RetryBootNS = 0
		if err := e.persist(); err != nil {
			t.Fatal(err)
		}
		e, c = reopenDeployment(t, e, c, dir)
		r, err := e.RebuildInstallations(context.Background(), installationWitness(t))
		if err != nil && r.Reason != "installation_cleanup_failed" {
			t.Fatal(r, err)
		}
		for _, v := range k.objects {
			if v.lease.Active {
				t.Fatal("failed cleanup or new installation enabled traffic")
			}
		}
		if i := e.index("ep1"); i >= 0 && e.journal.Entries[i].Phase == "applied" {
			if e.journal.Installations[0].Failures == 0 || e.journal.Installations[0].Reason != "installation_cleanup_failed" {
				t.Fatal("revoked cleanup failure was not recorded")
			}
			return
		}
	}
	t.Fatal("revoked endpoint cleanup starved independent installation")
}
