// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayplan"
)

type cliPlanIssuer struct {
	state     *relaycatalog.State
	env       relaycatalog.Environment
	getError  error
	bindError error
}

func (f *cliPlanIssuer) RelayCatalog(_ context.Context, node string) (relaycatalog.View, error) {
	return f.state.NodeView(node), f.getError
}
func (f *cliPlanIssuer) BindRelayPath(_ context.Context, r relaycatalog.BindRequest) (relaycatalog.View, error) {
	if f.bindError != nil {
		return relaycatalog.View{}, f.bindError
	}
	next, e := relaycatalog.Bind(f.state, r, f.env, time.Now().UTC())
	if e == nil {
		f.state = next
	}
	return f.state.NodeView(r.NodeID), e
}

func TestRelayPlanCLIRejectsUnusableApprovals(t *testing.T) {
	for _, mode := range []string{"missing", "foreign-node", "foreign-controller", "expired", "expires-during-plan", "denied", "uncertain-controller", "disabled", "draining", "unbound", "oversized", "unmapped"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			cacheDir := filepath.Join(dir, "cache")
			cfg := config.Config{Node: &config.NodeConfig{Name: "robot-a", Controller: "https://unused.invalid", PKIDir: dir, RelayCacheDir: cacheDir}}
			spec, e := readRelaySpec("../../configs/relay-catalog.example.json")
			if e != nil {
				t.Fatal(e)
			}
			for i := range spec.Paths {
				if mode == "disabled" {
					spec.Paths[i].Disabled = true
				}
				if mode == "draining" {
					spec.Paths[i].Drain = true
				}
			}
			env := relaycatalog.Environment{Nodes: map[string]bool{"robot-a": true}, VPNCIDR: "10.7.0.0/24"}
			at, ttl := time.Now().UTC(), 3600
			if mode == "expired" || mode == "expires-during-plan" {
				at = at.Add(-time.Minute)
				ttl = 65
			}
			state, e := relaycatalog.Apply(nil, relaycatalog.Update{Spec: spec, TTLSeconds: ttl}, env, at)
			if e != nil {
				t.Fatal(e)
			}
			issuer := &cliPlanIssuer{state: state, env: env}
			if mode != "missing" {
				cache, e := relaycache.Open(cacheDir, relaycache.Options{NodeID: "robot-a", Create: true})
				if e != nil {
					t.Fatal(e)
				}
				if mode == "unbound" {
					issuer.bindError = fmt.Errorf("fixture binding failure")
				}
				_, e = cache.Refresh(context.Background(), issuer)
				if e != nil && mode != "unbound" {
					cache.Close()
					t.Fatal(e)
				}
				switch mode {
				case "denied":
					issuer.getError = &api.HTTPError{StatusCode: 403}
				case "uncertain-controller":
					issuer.getError = &api.HTTPError{StatusCode: 503, Code: "relay_catalog_uncertain"}
				}
				if issuer.getError != nil {
					if _, e = cache.Refresh(context.Background(), issuer); e == nil {
						cache.Close()
						t.Fatal("rejection not recorded")
					}
				}
				cache.Close()
			}
			if mode == "expired" {
				time.Sleep(time.Until(state.ExpiresAt) + 20*time.Millisecond)
			}
			if mode == "foreign-node" {
				cfg.Node.Name = "other"
			}
			if mode == "oversized" {
				path := filepath.Join(cacheDir, "state.json")
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var disk map[string]any
				if e = json.Unmarshal(raw, &disk); e != nil {
					t.Fatal(e)
				}
				catalog := disk["catalog"].(map[string]any)
				desc := catalog["spec"].(map[string]any)
				paths := desc["paths"].([]any)
				for len(paths) < 9 {
					paths = append(paths, paths[0])
				}
				desc["paths"] = paths
				raw, _ = json.Marshal(disk)
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "expires-during-plan" {
				cfg.Node.RelayUnderlays = []relayplan.Underlay{{ID: "wifi-main", Interface: "wan0", Kind: "wifi"}, {ID: "ethernet", Interface: "wan1", Kind: "ethernet"}}
				fakeBin := filepath.Join(dir, "bin")
				if e = os.Mkdir(fakeBin, 0700); e != nil {
					t.Fatal(e)
				}
				script := `#!/bin/sh
printf . >> "$VPNCTL_TEST_INVENTORY_MARKER"
sleep 1
if [ "$2" = "address" ]; then
 printf '%s\n' '[{"ifindex":7,"ifname":"wan0","flags":["UP","LOWER_UP"],"addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"scope":"global"}]},{"ifindex":8,"ifname":"wan1","flags":["UP","LOWER_UP"],"addr_info":[{"family":"inet","local":"198.51.100.10","prefixlen":24,"scope":"global"}]}]'
else
 printf '[{"dst":"%s","from":"%s","dev":"%s"}]\n' "$5" "$7" "$9"
fi
`
				if e = os.WriteFile(filepath.Join(fakeBin, "ip"), []byte(script), 0700); e != nil {
					t.Fatal(e)
				}
				t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
				t.Setenv("VPNCTL_TEST_INVENTORY_MARKER", filepath.Join(dir, "collected"))
			}
			path := filepath.Join(dir, "node.yaml")
			if e = config.Save(path, cfg); e != nil {
				t.Fatal(e)
			}
			args := []string{"node", "relay", "plan", "--config", path}
			if mode == "foreign-controller" {
				args = append(args, "--controller-id", strings.Repeat("0", 32))
			}
			cmd := cliProcess(t, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			raw, e := cmd.Output()
			if e == nil {
				t.Fatal("unusable approval accepted", mode)
			}
			prepareArgs := append([]string{}, args...)
			prepareArgs[2] = "prepare"
			prepareArgs = append(prepareArgs, "--path-id", spec.Paths[0].ID)
			if b, err := cliProcess(t, prepareArgs...).CombinedOutput(); err == nil || strings.Contains(string(b), `"kernel_ready":true`) || strings.Contains(string(b), "private_key") {
				t.Fatal("unusable preparation accepted or exposed secret", mode, err)
			}
			if strings.Contains(string(raw), "private_key") || strings.Contains(stderr.String(), "private_key") {
				t.Fatal("private field exposed")
			}
			if mode == "foreign-node" || mode == "oversized" {
				if len(raw) != 0 {
					t.Fatal("corrupt cache produced usable plan")
				}
				return
			}
			var plan relayplan.Plan
			if e = json.Unmarshal(raw, &plan); e != nil {
				t.Fatalf("no structured rejection for %s: %v %s", mode, e, stderr.String())
			}
			if plan.State == "eligible" || plan.Reason == "" {
				t.Fatal("missing rejection reason", mode, plan)
			}
			for _, p := range plan.Paths {
				if p.Pin != nil || p.Reason == "" {
					t.Fatal("unusable path retained", mode, p)
				}
			}
			if mode == "disabled" || mode == "draining" {
				for _, p := range plan.Paths {
					if p.Reason != mode {
						t.Fatal(mode, p)
					}
				}
			}
			if (mode == "expired" || mode == "expires-during-plan") && (plan.CacheValidity != "expired" || !strings.Contains(plan.Reason, "expired")) {
				t.Fatal("expiry hidden", plan.Reason)
			}
			if mode == "expires-during-plan" {
				if b, e := os.ReadFile(filepath.Join(dir, "collected")); e != nil || len(b) == 0 {
					t.Fatal("cache expired before collection; boundary was not exercised")
				}
			}
			if mode == "denied" && !strings.Contains(plan.Reason, "denied") {
				t.Fatal("denial hidden", plan.Reason)
			}
		})
	}
}

func TestRelayPlanConfigExample(t *testing.T) {
	cfg, e := config.Load("../../configs/node-relay-plan.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if e = config.Validate(cfg); e != nil {
		t.Fatal(e)
	}
	spec, e := readRelaySpec("../../configs/relay-catalog.example.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range spec.Paths {
		found := false
		for _, u := range cfg.Node.RelayUnderlays {
			found = found || path.UnderlayID == u.ID
		}
		if !found {
			t.Fatal("example catalog underlay missing", path.UnderlayID)
		}
	}
}
