// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

func installationWitness(t *testing.T) FreshApproval {
	t.Helper()
	f, err := ObserveApproval()
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func installationReady(t *testing.T, e *DeploymentEngine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := awaitInstallationReady(ctx, e); err != nil {
		t.Fatal(err, e.installationStatus())
	}
}
func TestRelayInstallationExplicitConsentAndFreshAuthority(t *testing.T) {
	e, k, c, f, o, dir := deploymentFixture(t, 1)
	if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil || len(k.objects) != 0 {
		t.Fatal("implicit install", err)
	}
	r, err := e.RequestInstallation(context.Background(), o)
	if err != nil || r.KernelReady || len(k.objects) != 0 || len(r.Installations) != 1 || !r.Installations[0].Enabled {
		t.Fatal(r, err)
	}
	raw, _ := json.Marshal(r)
	secret, _ := os.ReadFile(o.KeyFile)
	if strings.Contains(string(raw), o.KeyFile) || strings.Contains(string(raw), strings.TrimSpace(string(secret))) {
		t.Fatal("private key reference or material leaked")
	}
	for _, fresh := range []FreshApproval{{}, {At: time.Now().Add(-6 * time.Second), BootNS: 1}} {
		if _, err := e.RebuildInstallations(context.Background(), fresh); err == nil || len(k.objects) != 0 {
			t.Fatal("stale witness installed", err)
		}
	}
	// Reopening preserves intent but does not manufacture a request witness.
	e, c = reopenDeployment(t, e, c, dir)
	if _, err := e.RebuildInstallations(context.Background(), FreshApproval{}); err == nil || len(k.objects) != 0 {
		t.Fatal("disk replay installed", err)
	}
	fresh := installationWitness(t)
	if _, err := c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RebuildInstallations(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 7; n++ {
		// Maintain must not down an initially closed partial link between units.
		e.Maintain(context.Background(), FreshApproval{})
		if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil {
			t.Fatal(err)
		}
		if k.objects[o.EndpointID].lease.Active {
			t.Fatal("installation opened lease")
		}
	}
	if e.journal.Entries[0].Phase != "applied" {
		t.Fatal(e.journal)
	}
	if _, err := e.Maintain(context.Background(), FreshApproval{}); err == nil || k.objects[o.EndpointID].lease.Active {
		t.Fatal("cached approval rearmed", err)
	}
	if r, err := e.Maintain(context.Background(), installationWitness(t)); err != nil || !r.KernelReady {
		t.Fatal(r, err)
	}
	// Denial removes ownership but retains the local desired state.
	f.err = &api.HTTPError{StatusCode: 403}
	c.Refresh(context.Background(), f)
	e.Maintain(context.Background(), FreshApproval{})
	if len(k.objects) != 0 || len(e.journal.Entries) != 0 || len(e.journal.Installations) != 1 {
		t.Fatal("withdrawal state", e.journal)
	}
	if _, err := e.RebuildInstallations(context.Background(), FreshApproval{}); err == nil || len(k.objects) != 0 {
		t.Fatal("revocation replay", err)
	}
	f.err = nil
	if _, err := c.Refresh(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	installationReady(t, e)
	if k.objects[o.EndpointID].lease.Active {
		t.Fatal("reinstallation opened lease")
	}
	if r, err := e.Maintain(context.Background(), installationWitness(t)); err != nil || !r.KernelReady {
		t.Fatal(r, err)
	}
	if r, err := e.Release(context.Background(), o.EndpointID); err != nil || len(r.Installations) != 0 || len(k.objects) != 0 {
		t.Fatal(r, err)
	}
	e, c = reopenDeployment(t, e, c, dir)
	if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil || len(k.objects) != 0 {
		t.Fatal("release resurrected", err)
	}
}

func TestRelayInstallationDoesNotAdoptManualOrChangeIntent(t *testing.T) {
	e, _, _, _, o, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequestInstallation(context.Background(), o); !errors.Is(err, ErrConflict) {
		t.Fatal("adopted manual entry", err)
	}
	if _, err := e.Release(context.Background(), o.EndpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(context.Background(), o); !errors.Is(err, ErrConflict) {
		t.Fatal("manual apply bypassed intent", err)
	}
	revision := e.journal.Installations[0].Revision
	for n := 0; n < 100; n++ {
		if _, err := e.RequestInstallation(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.journal.Installations) != 1 || e.journal.Installations[0].Revision != revision {
		t.Fatal("repeat enrollment churn")
	}
	o.ListenPort++
	if _, err := e.RequestInstallation(context.Background(), o); !errors.Is(err, ErrConflict) {
		t.Fatal("intent changed implicitly", err)
	}
}

func TestRelayInstallationReleaseBeforeFailedJournalOrCleanup(t *testing.T) {
	for _, mode := range []string{"journal-before", "journal-after", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c, _, o, dir := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			installationReady(t, e)
			if mode == "foreign" {
				k.foreign = true
			} else {
				e.cache = &failingDeploymentCache{deploymentCache: e.cache, failAt: 1, after: mode == "journal-after"}
			}
			if _, err := e.Release(context.Background(), o.EndpointID); err == nil {
				t.Fatal("failure hidden")
			}
			k.foreign = false
			e, c = reopenDeployment(t, e, c, dir)
			e.Maintain(context.Background(), installationWitness(t))
			if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil {
				t.Fatal(err)
			}
			if len(k.objects) != 0 || len(e.journal.Installations) != 0 {
				t.Fatal("accepted opt-out resurrected", e.journal)
			}
		})
	}
}

func TestRelayInstallationCrashAtEveryKernelStep(t *testing.T) {
	for _, step := range deploymentInstallSteps {
		t.Run(step, func(t *testing.T) {
			e, k, c, _, o, dir := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			k.fail, k.after, k.crash = step, true, true
			crashed := false
			for n := 0; n < 10 && !crashed; n++ {
				func() {
					defer func() {
						if recover() != nil {
							crashed = true
						}
					}()
					e.RebuildInstallations(context.Background(), installationWitness(t))
				}()
			}
			if !crashed || !e.journal.Installations[0].InFlight {
				t.Fatal("crash not reached", step)
			}
			old := e.journal.Entries[0].Alias
			e, c = reopenDeployment(t, e, c, dir)
			k.fail, k.crash = "", false
			// Cleanup does not need fresh authority, but it may not replay the add.
			if _, err := e.RebuildInstallations(context.Background(), FreshApproval{}); err != nil || len(k.objects) != 0 {
				t.Fatal("interrupted installation replayed", err)
			}
			installationReady(t, e)
			if e.journal.Entries[0].Alias == old || k.objects[o.EndpointID].lease.Active {
				t.Fatal("owner reused or lease opened")
			}
		})
	}
}

func TestRelayInstallationStorageFailureAtEveryBoundary(t *testing.T) {
	// Enrollment (journal then independent consent) followed by each creation
	// cursor, ownership write, in-flight marker and completion write.
	for point := 1; point <= 23; point++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("write%d/after%v", point, after), func(t *testing.T) {
				e, k, c, _, o, dir := deploymentFixture(t, 1)
				fault := &failingDeploymentCache{deploymentCache: e.cache, failAt: point, after: after}
				e.cache = fault
				_, err := e.RequestInstallation(context.Background(), o)
				for n := 0; n < 12 && err == nil; n++ {
					_, err = e.RebuildInstallations(context.Background(), installationWitness(t))
				}
				if !errors.Is(err, errDeploymentStorageInjected) || fault.calls != point {
					t.Fatalf("wrong storage boundary failure: point=%d calls=%d err=%v", point, fault.calls, err)
				}
				for _, v := range k.objects {
					if v.lease.Active {
						t.Fatal("failed persistence granted traffic")
					}
				}
				e, c = reopenDeployment(t, e, c, dir)
				if err := validateInstallations(e.journal); err != nil {
					t.Fatal(err)
				}
				// Enrollment interrupted before consent cannot install; otherwise reopen
				// cleans an uncertain add and resumes with a new authenticated witness.
				if len(e.journal.Installations) == 0 {
					return
				}
				allowed, err := c.InstallationConsent(o.EndpointID, e.journal.Installations[0].Revision)
				if err != nil {
					t.Fatal(err)
				}
				if !allowed {
					if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err != nil || len(k.objects) != 0 {
						t.Fatal(err)
					}
					return
				}
				installationReady(t, e)
			})
		}
	}
}

func TestRelayInstallationExpiryDuringEveryStep(t *testing.T) {
	for _, step := range deploymentInstallSteps {
		t.Run(step, func(t *testing.T) {
			e, k, c, _, o, _ := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			expiry := &expiringDeploymentCache{deploymentCache: c}
			e.cache = expiry
			k.hook = func(s string) {
				if s == step {
					expiry.expired = true
				}
			}
			var err error
			for n := 0; n < 10 && err == nil; n++ {
				_, err = e.RebuildInstallations(context.Background(), installationWitness(t))
			}
			if err == nil || !expiry.expired {
				t.Fatal("expiry injection missed", step)
			}
			for _, o := range k.objects {
				if o.lease.Active {
					t.Fatal("expired step granted traffic")
				}
			}
			e.Maintain(context.Background(), FreshApproval{})
			if len(k.objects) != 0 || len(e.journal.Entries) != 0 || len(e.journal.Installations) != 1 {
				t.Fatal("expiry cleanup/intent lost")
			}
		})
	}
}

func TestRelayInstallationKeyRotationAndBackoff(t *testing.T) {
	for _, kind := range []string{"file", "unsafe-file", "generation", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			e, k, c, f, o, _ := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file":
				if err := os.WriteFile(o.KeyFile, []byte("mismatched"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsafe-file":
				if err := os.Chmod(o.KeyFile, 0644); err != nil {
					t.Fatal(err)
				}
			case "generation":
				f.view.Generation++
				f.view.Spec.Relays[0].KeyGeneration++
				for i := range f.view.Bindings {
					for _, p := range f.view.Spec.Paths {
						if p.ID == f.view.Bindings[i].PathID {
							f.view.Bindings[i].DefinitionHash = relaycatalog.DefinitionHash(f.view.Spec, p)
						}
					}
				}
				if _, err := c.Refresh(context.Background(), f); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				f.err = &api.HTTPError{StatusCode: 403}
				c.Refresh(context.Background(), f)
			}
			if _, err := e.RebuildInstallations(context.Background(), installationWitness(t)); err == nil {
				t.Fatal("invalid key/authority accepted", kind)
			}
			p := e.journal.Installations[0]
			if p.Failures != 1 || p.RetryBootNS == 0 {
				t.Fatal("retry backoff missing", p)
			}
			for n := 0; n < 100; n++ {
				e.RebuildInstallations(context.Background(), installationWitness(t))
			}
			if len(k.objects) != 0 || e.journal.Installations[0].Attempts != 0 || e.journal.Installations[0].Failures != 1 {
				t.Fatal("retry flood created resources or bypassed backoff")
			}
		})
	}
}

func TestRelayInstallationBudgetAndBootDomain(t *testing.T) {
	e, k, c, _, o, _ := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.RebuildInstallations(ctx, installationWitness(t)); !errors.Is(err, context.Canceled) || len(k.objects) != 0 {
		t.Fatal("cancelled creation", err)
	}
	fresh := installationWitness(t)
	fresh.BootNS += uint64(time.Minute)
	if _, err := e.RebuildInstallations(context.Background(), fresh); err == nil || len(k.objects) != 0 {
		t.Fatal("future boot witness installed")
	}
	for _, domain := range []string{"other-boot:net", "boot:other-net"} {
		if _, err := openDeploymentEngine(c, domain, k); err == nil || len(k.objects) != 0 {
			t.Fatal("domain mismatch adopted journal", domain, err)
		}
	}
	installationReady(t, e)
	if _, err := e.Maintain(context.Background(), installationWitness(t)); err != nil {
		t.Fatal(err)
	}
	// The old binary's schema gate must fail even after all intents are removed;
	// release does not silently downgrade the journal to an older contract.
	if _, err := e.Release(context.Background(), o.EndpointID); err != nil {
		t.Fatal(err)
	}
	if e.journal.Version != 2 {
		t.Fatal("silent downgrade")
	}
}

func TestRelayInstallationOwnedDriftAndForeignPreservation(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			e, k, _, _, o, _ := deploymentFixture(t, 1)
			if _, err := e.RequestInstallation(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			installationReady(t, e)
			if _, err := e.Maintain(context.Background(), installationWitness(t)); err != nil {
				t.Fatal(err)
			}
			old := e.journal.Entries[0].Alias
			if foreign {
				k.foreign = true
			} else {
				v := k.objects[o.EndpointID]
				v.up = false
				k.objects[o.EndpointID] = v
			}
			e.Maintain(context.Background(), installationWitness(t))
			_, err := e.RebuildInstallations(context.Background(), installationWitness(t))
			if foreign {
				if err == nil || len(k.objects) != 1 || e.journal.Entries[0].Alias != old {
					t.Fatal("foreign object altered", err)
				}
				return
			}
			if err != nil || len(k.objects) != 0 {
				t.Fatal("owned drift not removed", err)
			}
			installationReady(t, e)
			if e.journal.Entries[0].Alias == old || k.objects[o.EndpointID].lease.Active {
				t.Fatal("drift reused owner or opened lease")
			}
		})
	}
}

type failedInstallationDown struct {
	deploymentBackend
	renewals int
}

func (b *failedInstallationDown) Down(context.Context, DeploymentEntry) error {
	return errors.New("temporary cleanup failure")
}
func (b *failedInstallationDown) Lease(ctx context.Context, entry DeploymentEntry, until time.Time, fresh FreshApproval) (DeploymentLease, error) {
	b.renewals++
	return b.deploymentBackend.Lease(ctx, entry, until, fresh)
}
func TestRelayInstallationRevokedConsentCannotRenewAfterCleanupFailure(t *testing.T) {
	e, k, c, _, o, _ := deploymentFixture(t, 1)
	if _, err := e.RequestInstallation(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	installationReady(t, e)
	if _, err := e.Maintain(context.Background(), installationWitness(t)); err != nil {
		t.Fatal(err)
	}
	before := k.objects[o.EndpointID].lease.Deadline
	if err := c.RevokeInstallation(o.EndpointID); err != nil {
		t.Fatal(err)
	}
	b := &failedInstallationDown{deploymentBackend: e.backend}
	e.backend = b
	if _, err := e.Maintain(context.Background(), installationWitness(t)); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if b.renewals != 0 || !k.objects[o.EndpointID].lease.Deadline.Equal(before) {
		t.Fatal("revoked consent extended traffic after failed cleanup")
	}
}
