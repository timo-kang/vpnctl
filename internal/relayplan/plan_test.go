// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

type fixtureController struct {
	state *relaycatalog.State
	env   relaycatalog.Environment
}

func (f *fixtureController) RelayCatalog(_ context.Context, node string) (relaycatalog.View, error) {
	return f.state.NodeView(node), nil
}
func (f *fixtureController) BindRelayPath(_ context.Context, r relaycatalog.BindRequest) (relaycatalog.View, error) {
	next, e := relaycatalog.Bind(f.state, r, f.env, time.Now().UTC())
	if e == nil {
		f.state = next
	}
	return f.state.NodeView(r.NodeID), e
}
func public(label string) string {
	s := sha256.Sum256([]byte(label))
	k, _ := ecdh.X25519().NewPrivateKey(s[:])
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func planFixture(t *testing.T, node string) (relaycache.Report, []Underlay) {
	t.Helper()
	spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Protocol: "tcp", Port: 443}}}
	underlays := []Underlay{}
	for u := 0; u < 4; u++ {
		underlays = append(underlays, Underlay{ID: fmt.Sprintf("lan%d", u), Interface: fmt.Sprintf("eth%d", u), Kind: "ethernet"})
	}
	for r := 0; r < 2; r++ {
		relay := relaycatalog.Relay{ID: fmt.Sprintf("relay%d", r), PublicKey: public(fmt.Sprint("relay", r)), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: fmt.Sprintf("192.0.2.%d:51820", r+1)}}}
		spec.Relays = append(spec.Relays, relay)
		for u := 0; u < 4; u++ {
			spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p%d%d", r, u), NodeID: node, RelayID: relay.ID, EndpointID: "e", UnderlayID: underlays[u].ID, TargetIDs: []string{"app"}})
		}
	}
	env := relaycatalog.Environment{Nodes: map[string]bool{node: true}, VPNCIDR: "10.7.0.0/24"}
	state, e := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: spec}, env, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := relaycache.Open(dir, relaycache.Options{NodeID: node, Create: true})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	report, e := s.Refresh(context.Background(), &fixtureController{state, env})
	if e != nil {
		t.Fatal(e)
	}
	return report, underlays
}

type collectorFunc func(context.Context, Underlay, []string) Inventory

func (f collectorFunc) Collect(ctx context.Context, u Underlay, e []string) Inventory {
	return f(ctx, u, e)
}
func healthy(_ context.Context, u Underlay, endpoints []string) Inventory {
	yes := true
	source := "192.0.2.10"
	if u.SourceIPv4 != "" {
		source = u.SourceIPv4
	}
	v := Inventory{Underlay: u, Check: Check{State: "up"}, ObservedAt: time.Now().UTC(), IfIndex: 3, Present: &yes, AdminUp: &yes, Carrier: &yes, Addresses: []string{source}, DNS: unknown("not_collected"), Modem: unknown("not_collected")}
	for _, ep := range endpoints {
		v.Routes = append(v.Routes, Route{Check: Check{State: "up"}, Endpoint: ep, Source: source})
	}
	return v
}
func TestPlanVariableFleetAndCandidateLimits(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			for n := 0; n < size; n++ {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					t.Parallel()
					node := fmt.Sprintf("robot-%d", n)
					r, u := planFixture(t, node)
					for i := range u {
						u[i].SourceIPv4 = fmt.Sprintf("192.0.%d.%d", n+2, i+10)
					}
					p, e := Build(context.Background(), node, r.ControllerID, r, u, collectorFunc(healthy))
					if e != nil || p.State != "eligible" || len(p.Paths) != 8 || len(p.Inventory) != 4 || p.Applied || p.UplinkHealth != "unknown" {
						t.Fatalf("%+v %v", p, e)
					}
					seen := map[uint32]bool{}
					for _, path := range p.Paths {
						if path.State != "eligible" || path.Pin == nil || path.Pin.Source != u[indexUnderlay(u, path.UnderlayID)].SourceIPv4 || !path.Pin.TerminalUnreachable || !path.Pin.RequiresOwnershipCheck || seen[path.Pin.Table] {
							t.Fatal("mixed or incomplete candidate", path)
						}
						seen[path.Pin.Table] = true
					}
					b, _ := json.Marshal(p)
					if strings.Contains(string(b), "private_key") {
						t.Fatal("secret field in public plan")
					}
				})
			}
		})
	}
}
func TestPlanFailsClosedForCacheAndInventory(t *testing.T) {
	for _, tc := range []struct {
		name, state, reason string
		change              func(*relaycache.Report, *[]Underlay)
		collector           collectorFunc
	}{
		{name: "missing", state: "blocked", reason: "cache_missing", change: func(r *relaycache.Report, _ *[]Underlay) { *r = relaycache.MissingReport("robot") }},
		{name: "expired", state: "blocked", reason: "cache_expired", change: func(r *relaycache.Report, _ *[]Underlay) { r.Validity = "expired" }},
		{name: "denied", state: "blocked", reason: "cache_authorization_denied", change: func(r *relaycache.Report, _ *[]Underlay) {
			r.BlockedReason = "authorization_denied"
			r.UsableCache = false
		}},
		{name: "uncertain", state: "blocked", reason: "cache_uncertain", change: func(r *relaycache.Report, _ *[]Underlay) { r.Validity = "uncertain" }},
		{name: "foreign-node", state: "blocked", reason: "cache_identity_mismatch", change: func(r *relaycache.Report, _ *[]Underlay) { r.NodeID = "other" }},
		{name: "foreign-controller", state: "blocked", reason: "catalog_invalid", change: func(r *relaycache.Report, _ *[]Underlay) { r.ControllerID = "different" }},
		{name: "oversize", state: "blocked", reason: "catalog_invalid", change: func(r *relaycache.Report, _ *[]Underlay) {
			r.Catalog.Spec.Paths = append(r.Catalog.Spec.Paths, r.Catalog.Spec.Paths[0])
		}},
		{name: "disabled", state: "blocked", reason: "no_prepared_candidates", change: func(r *relaycache.Report, _ *[]Underlay) {
			for i := range r.Catalog.Spec.Paths {
				r.Catalog.Spec.Paths[i].Disabled = true
			}
		}},
		{name: "unbound", state: "blocked", reason: "candidate_preparation_incomplete", change: func(r *relaycache.Report, _ *[]Underlay) { r.Paths = nil }},
		{name: "unmapped", state: "unknown", reason: "candidate_inventory_incomplete", change: func(_ *relaycache.Report, u *[]Underlay) { *u = nil }},
		{name: "absent", state: "no_uplink", reason: "approved_underlays_unavailable", collector: func(ctx context.Context, u Underlay, e []string) Inventory {
			v := healthy(ctx, u, e)
			v.Check = down("interface_absent")
			return v
		}},
		{name: "unknown", state: "unknown", reason: "candidate_inventory_incomplete", collector: func(ctx context.Context, u Underlay, e []string) Inventory {
			v := healthy(ctx, u, e)
			v.Check = unknown("permission_denied")
			return v
		}},
		{name: "stale", state: "unknown", reason: "candidate_inventory_incomplete", collector: func(ctx context.Context, u Underlay, e []string) Inventory {
			v := healthy(ctx, u, e)
			v.ObservedAt = v.ObservedAt.Add(-time.Minute)
			return v
		}},
		{name: "wrong-device", state: "unknown", reason: "candidate_inventory_incomplete", collector: func(ctx context.Context, u Underlay, e []string) Inventory {
			v := healthy(ctx, u, e)
			v.Interface = "other"
			return v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, u := planFixture(t, "robot")
			if tc.change != nil {
				tc.change(&r, &u)
			}
			c := tc.collector
			if c == nil {
				c = healthy
			}
			p, e := Build(context.Background(), "robot", "", r, u, c)
			if e != nil || p.State != tc.state || p.Reason != tc.reason {
				t.Fatalf("got %s/%s err=%v", p.State, p.Reason, e)
			}
			for _, v := range p.Paths {
				if v.Pin != nil {
					t.Fatal("excluded plan contains pin", v)
				}
			}
		})
	}
}
func TestPlanPartialAndCancellation(t *testing.T) {
	r, u := planFixture(t, "robot")
	c := collectorFunc(func(ctx context.Context, u Underlay, e []string) Inventory {
		v := healthy(ctx, u, e)
		if u.ID == "lan0" {
			v.Check = down("link_down")
		}
		return v
	})
	p, e := Build(context.Background(), "robot", "", r, u, c)
	if e != nil || p.State != "eligible" {
		t.Fatal(p, e)
	}
	excluded := 0
	for _, path := range p.Paths {
		if path.State == "excluded" {
			excluded++
			if path.Reason != "link_down" {
				t.Fatal(path)
			}
		}
	}
	if excluded != 2 {
		t.Fatal(excluded)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	p, e = Build(ctx, "robot", "", r, u, collectorFunc(func(ctx context.Context, u Underlay, e []string) Inventory { calls++; return healthy(ctx, u, e) }))
	if e != nil || p.State != "unknown" || calls != 0 {
		t.Fatal(p.State, e, calls)
	}
}
func TestUnderlayValidation(t *testing.T) {
	base := Underlay{ID: "lan", Interface: "eth0", Kind: "ethernet"}
	for _, v := range [][]Underlay{{base, base}, {{ID: "x", Interface: "-bad", Kind: "wifi"}}, {{ID: "x", Interface: "a", Kind: "lte", SourceIPv4: "::1"}}, {{ID: "x", Interface: "a", Kind: "ethernet", SourceIPv4: "127.0.0.1"}}, make([]Underlay, 5)} {
		if ValidateUnderlays(v) == nil {
			t.Fatal("invalid mappings accepted")
		}
	}
}

func TestPlanUnboundPathDoesNotInventNoUplink(t *testing.T) {
	r, u := planFixture(t, "robot")
	r.Paths = r.Paths[:1]
	p, e := Build(context.Background(), "robot", "", r, u, collectorFunc(func(ctx context.Context, u Underlay, ep []string) Inventory {
		v := healthy(ctx, u, ep)
		v.Check = down("link_down")
		return v
	}))
	if e != nil || p.State != "blocked" || p.Reason != "candidate_preparation_incomplete" {
		t.Fatal(p.State, p.Reason, e)
	}
}
func TestUnderlayYAMLRejectsMisspelledConstraints(t *testing.T) {
	for _, raw := range []string{"id: lan\ninterface: eth0\nkind: ethernet\nsource_ip: 192.0.2.1\n", "id: lan\ninterface: eth0\nkind: lte\nmodem: 0\n", "[lan, eth0]"} {
		var u Underlay
		if yaml.Unmarshal([]byte(raw), &u) == nil {
			t.Fatal("unknown underlay constraint ignored")
		}
	}
}
