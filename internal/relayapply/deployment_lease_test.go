// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycache"
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

type failedRemovalBackend struct {
	deploymentBackend
	failed string
}

func (b failedRemovalBackend) Down(ctx context.Context, e DeploymentEntry) error {
	err := b.deploymentBackend.Down(ctx, e)
	if e.Endpoint == b.failed {
		return errors.Join(err, ErrConflict)
	}
	return err
}

func TestLeaseCleanupConflictDoesNotStarveApprovedEndpoint(t *testing.T) {
	for _, mode := range []string{"conflict", "status-failure", "journal-uncertain"} {
		t.Run(mode, func(t *testing.T) {
			e, k, c, issuer, o, _ := deploymentFixture(t, 1)
			for _, ep := range []string{"ep0", "ep1"} {
				o.EndpointID = ep
				if ep == "ep1" {
					o.ListenPort = 51821
				}
				if _, err := e.Apply(context.Background(), o); err != nil {
					t.Fatal(err)
				}
			}
			issuer.view.Generation++
			paths := issuer.view.Spec.Paths[:0]
			removed := map[string]bool{}
			for _, p := range issuer.view.Spec.Paths {
				if p.EndpointID == "ep0" {
					removed[p.ID] = true
				} else {
					paths = append(paths, p)
				}
			}
			issuer.view.Spec.Paths = paths
			bindings := issuer.view.Bindings[:0]
			for _, b := range issuer.view.Bindings {
				if !removed[b.PathID] {
					bindings = append(bindings, b)
				}
			}
			issuer.view.Bindings = bindings
			if _, err := c.Refresh(context.Background(), issuer); err != nil {
				t.Fatal(err)
			}
			before := k.objects["ep1"].lease.Deadline
			e.backend = failedRemovalBackend{k, "ep0"}
			if mode == "status-failure" {
				e.cache = &failedLeaseRecheckCache{deploymentCache: c}
			}
			if mode == "journal-uncertain" {
				e.backend = k
				e.cache = &failingDeploymentCache{deploymentCache: c, failAt: 1}
			}
			if out, err := e.Maintain(context.Background(), FreshApproval{At: time.Now().UTC()}); err == nil || out.KernelReady {
				t.Fatal("cleanup conflict hidden", out, err)
			}
			if k.objects["ep0"].lease.Active {
				t.Fatal("invalid endpoint rearmed")
			}
			if advanced := k.objects["ep1"].lease.Deadline.After(before); advanced != (mode == "conflict") {
				t.Fatal("independent lease decision disagrees with approval/storage certainty", mode, advanced)
			}
		})
	}
}

type failedLeaseRecheckCache struct {
	deploymentCache
	calls int
}

func (c *failedLeaseRecheckCache) Status() (relaycache.DeploymentReport, error) {
	c.calls++
	r, err := c.deploymentCache.Status()
	if c.calls == 2 {
		return r, errors.New("read failed after cleanup conflict")
	}
	return r, err
}

func (b failedLeaseBackend) Lease(c context.Context, e DeploymentEntry, t time.Time, authenticatedAt FreshApproval) (DeploymentLease, error) {
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
	if r, err := e.Maintain(context.Background(), FreshApproval{At: time.Now().UTC()}); err == nil || r.KernelReady {
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
	if r, err := other.Maintain(context.Background(), FreshApproval{At: time.Now().UTC()}); err != nil || r.State != "empty" || len(k.objects) != 0 {
		t.Fatal("legacy peer was renewed without installing a guard", r, err)
	}
}

func TestLeaseMaintenanceRequiresFreshResponseAfterTimeout(t *testing.T) {
	e, k, _, _, o, _ := deploymentFixture(t, 3)
	if _, err := e.Apply(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if r, err := e.Maintain(context.Background(), FreshApproval{At: time.Time{}}); err != nil || !r.KernelReady {
		t.Fatal(r, err)
	}
	v := k.objects[o.EndpointID]
	v.lease = DeploymentLease{}
	k.objects[o.EndpointID] = v
	if r, err := e.Maintain(context.Background(), FreshApproval{At: time.Time{}}); err == nil || r.KernelReady {
		t.Fatal("cached approval restored expired lease", r, err)
	}
	if r, err := e.Maintain(context.Background(), FreshApproval{At: time.Now().Add(-6 * time.Second).UTC()}); err == nil || r.KernelReady {
		t.Fatal("response received before a long pause restored expired lease", r, err)
	}
	if r, err := e.Maintain(context.Background(), FreshApproval{At: time.Now().UTC()}); err != nil || !r.KernelReady {
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

func TestLeaseRoundedRearmWindowIsRetryableExpiry(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 10, 200_000_000, time.UTC)
	// The response is still younger than 5s, but the remaining 100ms cannot
	// form a whole-second nft deadline. Preserve the closed peer for a newer
	// response instead of classifying this as a kernel failure and taking it down.
	_, err := leaseDeadline(false, now.Add(time.Hour), now.Add(-4900*time.Millisecond), now)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatal("spent rearm window would force link teardown", err)
	}
	e, k, _, _, options, _ := deploymentFixture(t, 1)
	if _, err := e.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second).Add(200 * time.Millisecond)
	k.now = func() time.Time { return clock }
	peer := k.objects[options.EndpointID]
	peer.lease = DeploymentLease{}
	k.objects[options.EndpointID] = peer
	if out, err := e.Maintain(context.Background(), FreshApproval{At: clock.Add(-4900 * time.Millisecond)}); !errors.Is(err, ErrLeaseExpired) || out.KernelReady {
		t.Fatal("spent window accepted", out, err)
	}
	if peer := k.objects[options.EndpointID]; !peer.up || peer.lease.Active {
		t.Fatal("closed peer was torn down or rearmed")
	}
	if out, err := e.Maintain(context.Background(), FreshApproval{At: clock}); err != nil || !out.KernelReady {
		t.Fatal("new approval cannot rearm retained peer", out, err)
	}
}

func TestLeaseReadbackExpiryIsRetryableWithoutAcceptingInvalidInventory(t *testing.T) {
	engine, _, _, _, options, _ := deploymentFixture(t, 1)
	approval, _ := engine.cache.Status()
	entry, _ := desiredDeployment(approval, options.EndpointID, options.ListenPort)
	entry.Alias, entry.Group, entry.LinkIndex, _ = token()
	entry.LeaseVersion = 2
	for _, mode := range []string{"active", "zero-countdown", "empty-set", "missing", "wrong-deadline", "wrong-owner"} {
		t.Run(mode, func(t *testing.T) {
			committed := false
			selected := "lease_00000000000000000000000000000000"
			pending := ""
			deadline := time.Now().Add(-time.Second).Truncate(time.Second)
			backend := deploymentKernel{kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
				if name != "nft" {
					t.Fatal("unexpected command", name, args)
				}
				encode := func(rows []object) ([]byte, error) { return json.Marshal(object{"nftables": rows}) }
				switch strings.Join(args, " ") {
				case "-j -n -T list tables":
					if committed && mode == "missing" {
						return encode([]object{})
					}
					return encode(leaseExpected(entry, deadline)[:1])
				case "-j -n -T list flowtables":
					return encode([]object{})
				case "-j -n -T list table inet " + leaseTable(entry):
					observed := deadline
					if committed && mode == "wrong-deadline" {
						observed = observed.Add(time.Second)
					}
					rows := stagedLeaseTestRows(entry, observed, selected, pending)
					if committed && mode != "empty-set" {
						left := 1
						if mode == "zero-countdown" {
							left = 0 // nft rounds a subsecond remaining timeout to zero.
						}
						rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": entry.Interface, "expires": left}}}
					}
					if committed && mode == "wrong-owner" {
						rows[5]["rule"].(object)["comment"] = "foreign"
					}
					return encode(rows)
				case "-f /dev/stdin":
					if strings.Contains(input, "create set") {
						match := regexp.MustCompile(`create set inet [^ ]+ (lease_[0-9a-f]{32})`).FindStringSubmatch(input)
						if len(match) != 2 {
							t.Fatal("missing preparation", input)
						}
						pending = match[1]
						return nil, nil
					}
					selected, pending = pending, ""
					match := regexp.MustCompile(`meta time >= ([0-9]+)`).FindStringSubmatch(input)
					if len(match) != 2 {
						t.Fatal("missing lease cutoff")
					}
					seconds, err := strconv.ParseInt(match[1], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					deadline, committed = time.Unix(seconds, 0).UTC(), true
					return nil, nil
				default:
					return nil, fmt.Errorf("unexpected nft command %v", args)
				}
			}}}
			state, err := backend.Lease(context.Background(), entry, time.Now().Add(time.Hour), FreshApproval{At: time.Now().UTC()})
			if !committed {
				t.Fatal("lease commit not exercised", err)
			}
			if mode == "active" {
				if err != nil || !state.Active {
					t.Fatal("active lease rejected", state, err)
				}
			} else if mode == "zero-countdown" || mode == "empty-set" {
				if !errors.Is(err, ErrLeaseExpired) || state.Active {
					t.Fatal("normal expiry during readback would tear down the link", state, err)
				}
			} else if err == nil || errors.Is(err, ErrLeaseExpired) {
				t.Fatal("invalid inventory treated as retryable expiry", mode, state, err)
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
	if r, err := e.Maintain(ctx, FreshApproval{At: time.Now().UTC()}); err == nil || r.KernelReady {
		t.Fatal(r, err)
	}
	if backend.downDeadline.IsZero() || backend.downDeadline.After(want) {
		t.Fatal("supervisor inherited CLI recovery extension", backend.downDeadline, want)
	}
	if len(k.objects) != 0 {
		t.Fatal("expired peers survived final recheck")
	}
}
