//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetns_M3LeaseConflicts(t *testing.T) {
	requireNetwork(t)
	for _, fault := range []string{"foreign-peer-with-withdrawal", "preshared-key", "foreign-route", "foreign-guard-chain", "foreign-forward-policy", "missing-forward-policy", "flowtable"} {
		t.Run(fault, func(t *testing.T) {
			f := newM3AuthorityFixture(t)
			report := map[string]any{"schema_version": 1, "fault": fault, "completed": false}
			defer func() { writeM3Report(t, filepath.Join(f.results, "conflict.json"), report) }()
			r := f.recipients[0]
			initial := r.ready()
			iface := initial.Kernel.Endpoints[0].Interface
			guard := "vl" + iface[2:]
			_, pub := wgKeyPair(t)
			psk, _ := wgKeyPair(t)
			pskPath := filepath.Join(f.private, "foreign.psk")
			mustWrite(t, pskPath, psk)
			for _, p := range f.plan.Paths {
				if !f.probe(p).OK {
					t.Fatal("baseline inaccessible", p.PathID)
				}
			}
			report["before"] = initial
			report["fault_at"] = time.Now().UTC()
			switch fault {
			case "foreign-peer-with-withdrawal":
				netOutput(t, r.ns, "wg", "set", iface, "peer", pub, "allowed-ips", "203.0.113.1/32")
				spec := copyM3Spec(f.spec)
				spec.Paths[0].Disabled = true
				f.controller.apply(spec, 3600)
			case "preshared-key":
				netOutput(t, r.ns, "wg", "set", iface, "peer", f.plan.Paths[0].PublicKey, "preshared-key", pskPath)
			case "foreign-route":
				netOutput(t, r.ns, "ip", "route", "add", "203.0.113.1/32", "dev", iface)
			case "foreign-guard-chain":
				netOutput(t, r.ns, "nft", "add", "chain", "inet", guard, "foreign")
			case "foreign-forward-policy":
				netOutput(t, r.ns, "nft", "add", "chain", "inet", "vf"+iface[2:], "foreign")
			case "missing-forward-policy":
				netOutput(t, r.ns, "nft", "delete", "table", "inet", "vf"+iface[2:])
			case "flowtable":
				(relayUplink{relay: r.ns}).nft(t, `table inet foreign_flow {
 flowtable external { hook ingress priority 0; devices = { wan0 }; }
}`)
			}
			// Outlast an untouched lease. A one-off healthy probe would miss
			// starvation of another endpoint after cleanup encounters a conflict.
			time.Sleep(11 * time.Second)
			probes := map[string]m3Probe{}
			for i, p := range f.plan.Paths {
				want := i != 0
				if fault == "flowtable" && i == 1 {
					want = false
				}
				v := f.probe(p)
				probes[p.PathID] = v
				if v.OK != want {
					t.Fatalf("%s reachability=%t want=%t", p.PathID, v.OK, want)
				}
			}
			report["after_11s"] = probes
			switch fault {
			case "foreign-peer-with-withdrawal":
				if !strings.Contains(netOutput(t, r.ns, "wg", "show", iface, "peers"), pub) {
					t.Fatal("foreign peer removed")
				}
				netOutput(t, r.ns, "wg", "set", iface, "peer", pub, "remove")
				f.controller.apply(f.spec, 3600)
			case "preshared-key":
				// Compare in memory; never log/export a preshared key.
				if !strings.Contains(netOutput(t, r.ns, "wg", "show", iface, "preshared-keys"), strings.TrimSpace(psk)) {
					t.Fatal("foreign PSK altered")
				}
				netOutput(t, r.ns, "wg", "set", iface, "peer", f.plan.Paths[0].PublicKey, "preshared-key", "/dev/null")
			case "foreign-route":
				if !strings.Contains(netOutput(t, r.ns, "ip", "route", "show", "dev", iface), "203.0.113.1") {
					t.Fatal("foreign route removed")
				}
				netOutput(t, r.ns, "ip", "route", "del", "203.0.113.1/32", "dev", iface)
			case "foreign-guard-chain":
				netOutput(t, r.ns, "nft", "list", "chain", "inet", guard, "foreign")
				netOutput(t, r.ns, "nft", "delete", "chain", "inet", guard, "foreign")
			case "foreign-forward-policy":
				netOutput(t, r.ns, "nft", "list", "chain", "inet", "vf"+iface[2:], "foreign")
				if _, err := r.call("release", 0, 0); err == nil {
					t.Fatal("foreign policy silently removed")
				}
				netOutput(t, r.ns, "nft", "delete", "chain", "inet", "vf"+iface[2:], "foreign")
			case "missing-forward-policy":
				if strings.Contains(netOutput(t, r.ns, "nft", "list", "tables"), "vf"+iface[2:]) {
					t.Fatal("external deletion triggered automatic policy replacement")
				}
			case "flowtable":
				netOutput(t, r.ns, "nft", "list", "flowtable", "inet", "foreign_flow", "external")
				netOutput(t, r.ns, "nft", "delete", "table", "inet", "foreign_flow")
			}
			report["foreign_resource_preserved"] = true
			// Recreating a WG interface discards handshake state. Exercise
			// explicit installation of both sides, not seamless session recovery.
			for _, recipient := range f.recipients {
				recipient.watch.terminate(t)
				recipient.require("refresh", -1, 0)
				for ep := 0; ep < 2; ep++ {
					recipient.require("release", ep, 0)
				}
			}
			f.releaseNodeCandidates()
			f.install()
			for _, p := range f.plan.Paths {
				p := p
				eventually(t, 10*time.Second, "explicit recovery "+p.PathID, func() error {
					if !f.probe(p).OK {
						return fmt.Errorf("not reachable")
					}
					return nil
				})
			}
			report["completed"] = true
		})
	}
}

func writeM3Report(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Error(err)
		return
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Error(fmt.Errorf("write report: %w", err))
	}
}
