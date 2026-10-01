//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

// Only the approval issuer is a fixture here. Cache key generation, validation,
// the separate production CLI and its kernel inventory collector are real.
// The authenticated catalog/cache lifecycle is covered by the mTLS CLI suite.
type planIssuer struct {
	state *relaycatalog.State
	env   relaycatalog.Environment
}

func (p *planIssuer) RelayCatalog(_ context.Context, node string) (relaycatalog.View, error) {
	return p.state.NodeView(node), nil
}
func (p *planIssuer) RelayDeployment(_ context.Context, principal, relay string) (relaycatalog.DeploymentView, error) {
	v, ok := p.state.DeploymentFor(principal, relay)
	if !ok {
		return v, fmt.Errorf("fixture recipient not authorized")
	}
	return v, nil
}
func (p *planIssuer) BindRelayPath(_ context.Context, r relaycatalog.BindRequest) (relaycatalog.View, error) {
	n, e := relaycatalog.Bind(p.state, r, p.env, time.Now().UTC())
	if e == nil {
		p.state = n
	}
	return p.state.NodeView(r.NodeID), e
}

func checkM3LocalPlans(t *testing.T, robot string, relays []string, target, private string, relayKeys, publicKeys []string) {
	t.Helper()
	bin := integrationBinary(t)
	spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/16", Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{m3Target + "/32"}, ProbeAddress: m3Target, Port: 9192, Protocol: "tcp"}}}
	for r, key := range publicKeys {
		relay := relaycatalog.Relay{ID: fmt.Sprintf("r%d", r), PublicKey: key, KeyGeneration: 1}
		for u, prefix := range []string{"192.0.2", "198.51.100"} {
			ep := relaycatalog.Endpoint{ID: fmt.Sprintf("ep%d", u), Address: fmt.Sprintf("%s.%d:%d", prefix, 11+r, 51820+u)}
			relay.Endpoints = append(relay.Endpoints, ep)
			spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p%d%d", r, u), NodeID: "robot", RelayID: relay.ID, EndpointID: ep.ID, UnderlayID: fmt.Sprintf("lan%d", u), TargetIDs: []string{"app"}})
		}
		spec.Relays = append(spec.Relays, relay)
	}
	env := relaycatalog.Environment{Nodes: map[string]bool{"robot": true}, VPNCIDR: "10.77.0.0/24"}
	state, e := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: spec}, env, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	for _, relay := range spec.Relays {
		state, e = relaycatalog.SetRecipient(state, relaycatalog.RecipientUpdate{ControllerID: state.ControllerID, ExpectedGeneration: state.Generation, RelayID: relay.ID, PrincipalID: "robot"}, env)
		if e != nil {
			t.Fatal(e)
		}
	}
	issuer := &planIssuer{state, env}
	dir := filepath.Join(private, "plan-cache")
	cache, e := relaycache.Open(dir, relaycache.Options{NodeID: "robot", Create: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = cache.Refresh(context.Background(), issuer); e != nil {
		cache.Close()
		t.Fatal(e)
	}
	cache.Close()
	cfg := config.Config{Node: &config.NodeConfig{Name: "robot", Controller: "https://unused.invalid", PKIDir: private, RelayCacheDir: dir, RelayUnderlays: []relayplan.Underlay{{ID: "lan0", Interface: "wan0", Kind: "ethernet"}, {ID: "lan1", Interface: "wan1", Kind: "wifi"}}}}
	configPath := filepath.Join(private, "plan-node.yaml")
	save := func() {
		t.Helper()
		if e := config.Save(configPath, cfg); e != nil {
			t.Fatal(e)
		}
	}
	save()
	// Include an unrelated tunnel so accidental flushing/deletion is observable.
	netOutput(t, robot, "ip", "link", "add", "plan-sentinel", "type", "wireguard")
	defer netOutput(t, robot, "ip", "link", "del", "plan-sentinel")
	netOutput(t, robot, "wg", "set", "plan-sentinel", "fwmark", "3456")
	snapshot := func() string {
		t.Helper()
		parts := []string{}
		for _, args := range [][]string{{"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "-j", "rule", "show"}, {"ip", "-j", "link", "show"}, {"wg", "show", "all", "public-key"}, {"wg", "show", "all", "fwmark"}, {"wg", "show", "all", "endpoints"}, {"wg", "show", "all", "allowed-ips"}, {"wg", "show", "all", "listen-port"}} {
			parts = append(parts, netOutput(t, robot, args...))
		}
		return strings.Join(parts, "\n")
	}
	checks := 0
	plan := func(want string, eligible int) relayplan.Plan {
		t.Helper()
		checks++
		before := snapshot()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		cmd := netCommand(ctx, robot, bin, "node", "relay", "plan", "--config", configPath, "--controller-id", state.ControllerID)
		b, e := cmd.Output()
		var p relayplan.Plan
		if json.Unmarshal(b, &p) != nil {
			t.Fatalf("plan output unavailable: %v", e)
		}
		if p.State != want || (e == nil) != (want == "eligible") || p.Applied || p.UplinkHealth != "unknown" {
			t.Fatalf("unexpected plan %s/%s: %v", p.State, p.Reason, e)
		}
		n := 0
		for _, candidate := range p.Paths {
			if candidate.State == "eligible" {
				n++
				if candidate.Pin == nil || candidate.Pin.IfIndex <= 0 {
					t.Fatal("no concrete pin input")
				}
				route := netOutput(t, robot, "ip", "-j", "-4", "route", "get", strings.Split(candidate.Endpoint, ":")[0], "from", candidate.Pin.Source, "oif", candidate.Pin.Interface)
				if !strings.Contains(route, candidate.Pin.Source) {
					t.Fatal("source does not match kernel")
				}
			} else if candidate.Reason == "" {
				t.Fatal("silent candidate exclusion")
			}
		}
		if n != eligible {
			for _, path := range p.Paths {
				t.Log(path.PathID, path.State, path.Reason)
			}
			for _, inv := range p.Inventory {
				t.Log(inv.ID, inv.State, inv.Reason, inv.Addresses)
			}
			t.Fatalf("check=%d eligible=%d want=%d", checks, n, eligible)
		}
		if strings.Contains(string(b), "private_key") || before != snapshot() {
			t.Fatal("plan disclosed secrets or mutated kernel configuration")
		}
		return p
	}
	p := plan("eligible", 4)
	for _, c := range p.Paths {
		if c.Pin.Gateway != "" {
			t.Fatal("invented gateway for direct-connected endpoint")
		}
	}
	netOutput(t, robot, "ip", "route", "add", "192.0.2.11/32", "via", "192.0.2.12", "dev", "wan0")
	p = plan("eligible", 4)
	for _, c := range p.Paths {
		if c.PathID == "p00" && c.Pin.Gateway != "192.0.2.12" {
			t.Fatal("gateway selection lost", c.Pin)
		}
	}
	netOutput(t, robot, "ip", "route", "del", "192.0.2.11/32")
	netOutput(t, robot, "ip", "link", "set", "wan0", "down")
	plan("eligible", 2)
	netOutput(t, robot, "ip", "link", "set", "wan1", "down")
	plan("no_uplink", 0)
	netOutput(t, robot, "ip", "link", "set", "wan0", "up")
	netOutput(t, robot, "ip", "link", "set", "wan1", "up")
	netOutput(t, robot, "ip", "addr", "add", "192.0.2.20/24", "dev", "wan0")
	plan("eligible", 2)
	cfg.Node.RelayUnderlays[0].SourceIPv4 = "192.0.2.10"
	save()
	plan("eligible", 4)
	netOutput(t, robot, "ip", "addr", "del", "192.0.2.10/24", "dev", "wan0")
	plan("eligible", 2)
	netOutput(t, robot, "ip", "addr", "replace", "192.0.2.20/24", "dev", "wan0")
	cfg.Node.RelayUnderlays[0].SourceIPv4 = "192.0.2.20"
	save()
	p = plan("eligible", 4)
	for _, c := range p.Paths {
		if c.UnderlayID == "lan0" && c.Pin.Source != "192.0.2.20" {
			t.Fatal("stale source reused")
		}
	}
	netOutput(t, robot, "ip", "addr", "del", "192.0.2.20/24", "dev", "wan0")
	netOutput(t, robot, "ip", "addr", "replace", "192.0.2.10/24", "dev", "wan0")
	cfg.Node.RelayUnderlays[0].SourceIPv4 = ""
	save()
	netOutput(t, robot, "ip", "addr", "del", "192.0.2.10/24", "dev", "wan0")
	p = plan("eligible", 2)
	for _, inv := range p.Inventory {
		if inv.ID == "lan0" && (inv.Present == nil || !*inv.Present || inv.Reason != "no_ipv4") {
			t.Fatal("present device without IPv4 misclassified", inv)
		}
	}
	netOutput(t, robot, "ip", "addr", "replace", "192.0.2.10/24", "dev", "wan0")
	netOutput(t, robot, "ip", "link", "set", "wan0", "name", "renamed0")
	plan("eligible", 2)
	netOutput(t, robot, "ip", "link", "set", "renamed0", "name", "wan0")
	plan("eligible", 4)
	checkM3PreparedPaths(t, robot, relays, target, private, configPath, relayKeys, plan("eligible", 4), issuer)
	t.Log("M3 plan: two real underlays/four approved paths, no LTE or default route, repeated device/address changes; kernel configuration unchanged by CLI")
}
