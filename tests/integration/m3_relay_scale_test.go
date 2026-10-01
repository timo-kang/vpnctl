//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

// Measures real installed peer/route population, not a 32-node live traffic SLO.
func TestNetns_M3RelayDeploymentScale(t *testing.T) {
	requireNetwork(t)
	results, err := os.MkdirTemp(os.Getenv("VPNCTL_ARTIFACT_DIR"), "m3-relay-scale-")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			started := time.Now()
			ns := newNamespaces(t, 1)[0]
			private := t.TempDir()
			if err := os.Chmod(private, 0700); err != nil {
				t.Fatal(err)
			}
			key, pub := wgKeyPair(t)
			keyfile := filepath.Join(private, "relay.key")
			mustWrite(t, keyfile, key)
			spec := relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/16", Relays: []relaycatalog.Relay{{ID: "r", PublicKey: pub, KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "ep", Address: "192.0.2.1:51820"}}}}, Targets: []relaycatalog.Target{{ID: "app", Prefixes: []string{"198.18.0.2/32"}, ProbeAddress: "198.18.0.2", Port: 443, Protocol: "tcp"}}}
			env := relaycatalog.Environment{Nodes: map[string]bool{}, VPNCIDR: "10.77.0.0/24"}
			for n := 0; n < size; n++ {
				id := fmt.Sprintf("node-%d", n)
				env.Nodes[id] = true
				for p := 0; p < 4; p++ {
					spec.Paths = append(spec.Paths, relaycatalog.Path{ID: fmt.Sprintf("p-%d-%d", n, p), NodeID: id, RelayID: "r", EndpointID: "ep", UnderlayID: fmt.Sprintf("lan%d", p), TargetIDs: []string{"app"}})
				}
			}
			state, err := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: spec}, env, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{}
			for _, p := range spec.Paths {
				seed := sha256.Sum256([]byte(p.ID))
				k, err := ecdh.X25519().NewPrivateKey(seed[:])
				if err != nil {
					t.Fatal(err)
				}
				public := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
				state, err = relaycatalog.Bind(state, relaycatalog.BindRequest{SchemaVersion: 1, ControllerID: state.ControllerID, ExpectedGeneration: state.Generation, NodeID: p.NodeID, PathID: p.ID, PublicKey: public}, env, time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, b := range state.Bindings {
				want[b.PublicKey] = b.InnerAddress
			}
			state, err = relaycatalog.SetRecipient(state, relaycatalog.RecipientUpdate{ControllerID: state.ControllerID, ExpectedGeneration: state.Generation, RelayID: "r", PrincipalID: "node-0"}, env)
			if err != nil {
				t.Fatal(err)
			}
			cacheDir := filepath.Join(private, "cache")
			c, err := relaycache.OpenDeployment(cacheDir, relaycache.DeploymentOptions{PrincipalID: "node-0", RelayID: "r", Create: true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Refresh(context.Background(), &planIssuer{state, env})
			c.Close()
			if err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(private, "relay.yaml")
			if err = config.Save(cfgPath, config.Config{Node: &config.NodeConfig{Name: "node-0", PKIDir: private}}); err != nil {
				t.Fatal(err)
			}
			call := func(action string) relayapply.DeploymentResult {
				t.Helper()
				a := []string{integrationBinary(t), "relay", action, "--config", cfgPath, "--relay-id", "r", "--cache-dir", cacheDir}
				if action == "apply" || action == "release" {
					a = append(a, "--endpoint-id", "ep")
				}
				if action == "apply" {
					a = append(a, "--key-file", keyfile, "--key-generation", "1", "--listen-port", "51820")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
				defer cancel()
				b, err := netCommand(ctx, ns, a...).CombinedOutput()
				if strings.Contains(string(b), strings.TrimSpace(key)) {
					t.Fatal("private key leaked")
				}
				if err != nil {
					t.Fatalf("scale %s: %v %s", action, err, b)
				}
				var out relayapply.DeploymentResult
				if err = json.Unmarshal(b, &out); err != nil {
					t.Fatal(err)
				}
				return out
			}
			for attempt := 0; attempt < 3; attempt++ {
				out := call("apply")
				if !out.KernelReady || len(out.Endpoints) != 1 || out.Endpoints[0].Peers != size*4 {
					t.Fatal("wrong deployed population", out)
				}
				iface := out.Endpoints[0].Interface
				allowed := strings.Split(strings.TrimSpace(netOutput(t, ns, "wg", "show", iface, "allowed-ips")), "\n")
				if len(allowed) != len(want) {
					t.Fatal("wrong kernel peer count", len(allowed), len(want))
				}
				seen := map[string]bool{}
				for _, line := range allowed {
					f := strings.Fields(line)
					if len(f) != 2 || want[f[0]] != f[1] || seen[f[0]] {
						t.Fatal("wrong allowed IPs", line)
					}
					seen[f[0]] = true
				}
				var routes []map[string]any
				if err = json.Unmarshal([]byte(netOutput(t, ns, "ip", "-j", "-4", "route", "show", "dev", iface)), &routes); err != nil || len(routes) != len(want) {
					t.Fatal("wrong return route population", err, len(routes))
				}
				if out = call("inspect"); !out.KernelReady {
					t.Fatal(out)
				}
			}
			call("release")
			if out := call("inspect"); out.State != "empty" {
				t.Fatal("scale release incomplete", out)
			}
			if strings.TrimSpace(netOutput(t, ns, "wg", "show", "interfaces")) != "" {
				t.Fatal("owned interface survived")
			}
			report := map[string]any{"schema_version": 1, "completed": true, "nodes": size, "paths_per_node": 4, "kernel_peers": size * 4, "attempts": 3, "duration_ms": time.Since(started).Milliseconds(), "scope": "real peer/return-route population and repeated CLI reopen; fixture issuer; no full-fleet traffic SLO"}
			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(results, fmt.Sprintf("nodes-%d.json", size)), b, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}
