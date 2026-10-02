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
)

func TestNetns_M3LeaseSubsecondReadback(t *testing.T) {
	requireNetwork(t)
	f := newM3AuthorityFixture(t)
	r := f.recipients[0]
	before := r.ready()
	r.watch.terminate(t)
	ep := before.Kernel.Endpoints[0]
	table := "vl" + ep.Interface[2:]
	var inventory struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(netOutput(t, r.ns, "nft", "-j", "-n", "-T", "list", "table", "inet", table)), &inventory); err != nil {
		t.Fatal(err)
	}
	set := ""
	for _, row := range inventory.NFTables {
		if raw, ok := row["set"]; ok {
			var s struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(raw, &s); err != nil || set != "" || !strings.HasPrefix(s.Name, "lease_") {
				t.Fatal("unexpected lease sets", err)
			}
			set = s.Name
		}
	}
	if set == "" {
		t.Fatal("lease set missing")
	}
	// Record exactly the real nft JSON delivered to the product, so a timer
	// which vanished before inspection cannot silently pass this regression.
	dir := filepath.Join(f.private, "readback")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(f.results, "subsecond-nft.jsonl")
	script := "#!/bin/sh\ncase \"$*\" in\n'-j -n -T list table inet " + table + "')\n/usr/sbin/nft \"$@\" > '" + dir + "/out'\nstatus=$?\ncat '" + dir + "/out'\ncat '" + dir + "/out' >> '" + evidence + "'\nexit \"$status\"\n;;\n*) exec /usr/sbin/nft \"$@\";;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	(relayUplink{relay: r.ns}).nft(t, fmt.Sprintf("flush set inet %s %s\nadd element inet %s %s { %s timeout 800ms }\n", table, set, table, set, ep.Interface))
	r.start("PATH=" + dir + ":" + os.Getenv("PATH"))
	after := r.ready()
	data, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if err := json.Unmarshal([]byte(line), &inventory); err != nil {
			t.Fatal(err)
		}
		for _, row := range inventory.NFTables {
			var s struct {
				Elem []struct {
					Elem map[string]any `json:"elem"`
				} `json:"elem"`
			}
			if raw, ok := row["set"]; ok {
				if err := json.Unmarshal(raw, &s); err != nil {
					t.Fatal(err)
				}
				for _, e := range s.Elem {
					seen = seen || e.Elem["timeout"] == float64(0) && e.Elem["expires"] == float64(0)
				}
			}
		}
	}
	if !seen {
		t.Fatal("product did not observe a subsecond element")
	}
	recovered := after.Kernel.Endpoints[0]
	if recovered.Lease == nil || recovered.Lease.Boot == nil || ep.Lease == nil || ep.Lease.Boot == nil {
		t.Fatal("BOOTTIME identity evidence missing")
	}
	if recovered.Interface != ep.Interface || recovered.Lease.Boot.MapID != ep.Lease.Boot.MapID || recovered.Lease.Boot.ProgramID != ep.Lease.Boot.ProgramID {
		t.Fatal("recovery replaced managed resources")
	}
	for _, p := range f.plan.Paths {
		if !f.probe(p).OK {
			t.Fatal("fresh approval did not recover path", p.PathID)
		}
	}
}
