// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestLeaseRejectsAlteredRulesAndUnboundedCountdown(t *testing.T) {
	e, _, _, _, o, _ := deploymentFixture(t, 1)
	r, _ := e.cache.Status()
	v, _ := desiredDeployment(r, o.EndpointID, o.ListenPort)
	v.Alias, v.Group, v.LinkIndex, _ = token()
	for _, kind := range []string{"valid", "blocked", "expired", "zero-countdown", "element-timeout", "owner", "policy", "added-rule", "timeout", "wrong-index", "deadline", "dormant"} {
		t.Run(kind, func(t *testing.T) {
			deadline := time.Now().Add(8 * time.Second).Truncate(time.Second)
			if kind == "expired" {
				deadline = time.Now().Add(-time.Second).Truncate(time.Second)
			}
			b, _ := json.Marshal(leaseExpected(v, deadline))
			var rows []object
			json.Unmarshal(b, &rows)
			set := rows[1]["set"].(map[string]any)
			set["elem"] = []any{map[string]any{"elem": map[string]any{"val": v.Interface, "expires": float64(7)}}}
			rule := rows[5]["rule"].(map[string]any)
			switch kind {
			case "blocked":
				delete(set, "elem")
			case "owner":
				rule["comment"] = "other"
			case "policy":
				rows[2]["chain"].(map[string]any)["policy"] = "drop"
			case "added-rule":
				rows = append(rows, rows[5])
			case "timeout":
				set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["expires"] = float64(100)
			case "zero-countdown":
				set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
			case "element-timeout":
				set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["timeout"] = float64(100)
			case "wrong-index":
				set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["val"] = "other"
			case "deadline":
				rule["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)["right"] = "9999-01-01 00:00:00"
			case "dormant":
				rows[0]["table"].(map[string]any)["flags"] = []any{"dormant"}
			}
			got, err := validateLease(rows, v)
			valid := kind == "valid" || kind == "blocked" || kind == "expired" || kind == "zero-countdown"
			if (err == nil) != valid || valid && got.Active != (kind == "valid") {
				t.Fatal(kind, got, err)
			}
		})
	}
}

type failedLeaseBackend struct {
	deploymentBackend
	failed string
}

func (b failedLeaseBackend) Lease(c context.Context, e DeploymentEntry, t, authenticatedAt time.Time) (DeploymentLease, error) {
	if e.Endpoint == b.failed {
		return DeploymentLease{}, errors.New("flowtable or guard conflict")
	}
	return b.deploymentBackend.Lease(c, e, t, authenticatedAt)
}

func TestLeaseRenewalConflictQuiescesAndDoesNotSkipOtherEndpoints(t *testing.T) {
	e, k, _, _, o, _ := deploymentFixture(t, 3)
	for i := 0; i < 2; i++ {
		if i == 1 {
			o.EndpointID, o.ListenPort = "ep1", 51821
		}
		if _, err := e.Apply(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	e.backend = failedLeaseBackend{k, "ep0"}
	if r, err := e.Maintain(context.Background(), time.Now().UTC()); err == nil || r.KernelReady {
		t.Fatal(r, err)
	}
	if k.objects["ep0"].up || k.objects["ep0"].lease.Active {
		t.Fatal("unsafe endpoint left usable")
	}
	if !k.objects["ep1"].up || !k.objects["ep1"].lease.Active {
		t.Fatal("independent endpoint not maintained")
	}
}

func TestLegacyDeploymentCannotBeReportedLeaseProtected(t *testing.T) {
	e, k, c, _, o, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	e.journal.Entries[0].LeaseVersion = 0
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	if e.result("", "").ExpiryEnforcement != "legacy_on_command" {
		t.Fatal("legacy protection overstated")
	}
	other, err := openDeploymentEngine(c, "boot:net", k)
	if err != nil {
		t.Fatal("old typed journal no longer readable", err)
	}
	if r, err := other.Maintain(context.Background(), time.Now().UTC()); err != nil || r.State != "empty" || len(k.objects) != 0 {
		t.Fatal("legacy peer was renewed without installing a guard", r, err)
	}
}

func TestLeaseMaintenanceRequiresFreshResponseAfterTimeout(t *testing.T) {
	e, k, _, _, o, _ := deploymentFixture(t, 3)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Maintain(context.Background(), time.Time{}); err != nil || !r.KernelReady {
		t.Fatal(r, err)
	}
	v := k.objects[o.EndpointID]
	v.lease = DeploymentLease{}
	k.objects[o.EndpointID] = v
	if r, err := e.Maintain(context.Background(), time.Time{}); err == nil || r.KernelReady {
		t.Fatal("cached approval restored expired lease", r, err)
	}
	if r, err := e.Maintain(context.Background(), time.Now().Add(-6*time.Second).UTC()); err == nil || r.KernelReady {
		t.Fatal("response received before a long pause restored expired lease", r, err)
	}
	if r, err := e.Maintain(context.Background(), time.Now().UTC()); err != nil || !r.KernelReady {
		t.Fatal("fresh approval did not restore validated peers", r, err)
	}
}

func TestLeaseDeadlinesRemainBoundedAcrossClockAndResponseAge(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name             string
		active           bool
		expiry, received time.Time
		want             time.Time
	}{
		{"active-cache", true, now.Add(time.Hour), time.Time{}, now.Add(10 * time.Second)},
		{"near-expiry", true, now.Add(2 * time.Second), time.Time{}, now.Add(2 * time.Second)},
		{"fresh-rearm", false, now.Add(time.Hour), now, now.Add(5 * time.Second)},
		{"delayed-rearm", false, now.Add(time.Hour), now.Add(-4 * time.Second), now.Add(time.Second)},
		{"paused-response", false, now.Add(time.Hour), now.Add(-6 * time.Second), time.Time{}},
		{"clock-rollback", false, now.Add(time.Hour), now.Add(time.Second), time.Time{}},
		{"expired-approval", true, now.Add(-time.Second), now, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := leaseDeadline(tc.active, tc.expiry, tc.received, now)
			if (err != nil) != tc.want.IsZero() || !d.Equal(tc.want) {
				t.Fatal(d, err, tc.want)
			}
		})
	}
}

type leaseDeadlineBackend struct {
	deploymentBackend
	downDeadline time.Time
}

func (b *leaseDeadlineBackend) Down(ctx context.Context, e DeploymentEntry) error {
	b.downDeadline, _ = ctx.Deadline()
	return b.deploymentBackend.Down(ctx, e)
}

func TestLeaseSupervisorFinalCleanupDoesNotExtendCycleBudget(t *testing.T) {
	e, k, c, _, o, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	cache := &expiringDeploymentCache{deploymentCache: c}
	e.cache = cache
	backend := &leaseDeadlineBackend{deploymentBackend: k}
	e.backend = backend
	checks := 0
	k.checkHook = func() {
		checks++
		if checks == 2 {
			cache.expired = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	if r, err := e.Maintain(ctx, time.Now().UTC()); err == nil || r.KernelReady {
		t.Fatal(r, err)
	}
	if backend.downDeadline.IsZero() || backend.downDeadline.After(want) {
		t.Fatal("supervisor inherited CLI recovery extension", backend.downDeadline, want)
	}
	if len(k.objects) != 0 {
		t.Fatal("expired peers survived final recheck")
	}
}
