// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vpnctl/internal/relaycatalog"
)

func TestRelayCLIRejectsAmbiguousInputs(t *testing.T) {
	for _, raw := range []string{`{"schema_version":1,"typo":true}`, `{} {}`, strings.Repeat(" ", relaycatalog.MaxDocumentBytes+1)} {
		path := filepath.Join(t.TempDir(), "catalog.json")
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readRelaySpec(path); e == nil {
			t.Fatal("ambiguous/oversized document accepted")
		}
	}
	for _, args := range [][]string{{"apply"}, {"apply", "--file", "irrelevant", "--ttl", "59s"}, {"apply", "--file", "irrelevant", "--ttl", "1m1ms"}, {"status", "surprise"}} {
		if e := runControllerRelay(args); e == nil {
			t.Fatal("invalid command accepted", args)
		}
	}
	for _, args := range [][]string{{"bind"}, {"bind", "--controller-id", "id", "--generation", "1", "--path-id", "p", "--public-key", "bad"}, {"catalog", "surprise"}} {
		if e := runNodeRelay(args); e == nil {
			t.Fatal("invalid command accepted", args)
		}
	}
}

func TestRelayCatalogExampleContract(t *testing.T) {
	spec, e := readRelaySpec("../../configs/relay-catalog.example.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = relaycatalog.ValidateSpec(spec, relaycatalog.Environment{VPNCIDR: "10.7.0.0/24", Nodes: map[string]bool{"robot-a": true}}); e != nil {
		t.Fatal("documented example", e)
	}
}
