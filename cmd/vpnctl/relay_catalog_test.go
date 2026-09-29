// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"vpnctl/internal/api"
	"vpnctl/internal/relaycache"
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

// Called from the real CLI PKI lifecycle fixture: the catalog survives the same
// CA prepare/activate/rollback and backup/restore sequence as node identity.
func checkRelayCLIWorkflow(t *testing.T, run func(...string) string, controllerPath, nodePath string) {
	t.Helper()
	spec, e := readRelaySpec("../../configs/relay-catalog.example.json")
	if e != nil {
		t.Fatal(e)
	}
	for i := range spec.Paths {
		spec.Paths[i].NodeID = "a"
	}
	raw, e := json.Marshal(spec)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "relay.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var status api.AdminResponse
	if e = json.Unmarshal([]byte(run("controller", "relay", "apply", "--config", controllerPath, "--file", path)), &status); e != nil {
		t.Fatal(e)
	}
	if status.RelayCatalog == nil || status.RelayCatalog.Generation != 1 {
		t.Fatal("CLI did not publish catalog")
	}
	var view relaycatalog.View
	if e = json.Unmarshal([]byte(run("node", "relay", "catalog", "--config", nodePath)), &view); e != nil {
		t.Fatal(e)
	}
	if len(view.Spec.Paths) != 2 || view.NodeID != "a" {
		t.Fatal("CLI returned wrong catalog")
	}
	var report relaycache.Report
	if e = json.Unmarshal([]byte(run("node", "relay", "status", "--config", nodePath)), &report); e != nil || report.Validity != "missing" {
		t.Fatal("uninitialized cache status", e)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if e = json.Unmarshal([]byte(run("node", "relay", "refresh", "--config", nodePath)), &report); e != nil || !report.UsableCache || report.Preparation != "complete" || len(report.Paths) != 2 {
			t.Fatal("CLI refresh", e)
		}
	}
	if e = json.Unmarshal([]byte(run("node", "relay", "status", "--config", nodePath)), &report); e != nil || !report.UsableCache {
		t.Fatal("offline status", e)
	}
	cfg, err := loadConfig(nodePath)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := relaycache.Open(filepath.Join(cfg.Node.PKIDir, "relay-cache"), relaycache.Options{NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	out, childErr := cliProcess(t, "node", "relay", "refresh", "--config", nodePath).CombinedOutput()
	owner.Close()
	if childErr == nil || !strings.Contains(string(out), "relay cache is busy") {
		t.Fatal("second process did not reject cache ownership")
	}
	public := report.Paths[0].PublicKey
	args := []string{"node", "relay", "bind", "--config", nodePath, "--controller-id", view.ControllerID, "--generation", strconv.FormatUint(view.Generation, 10), "--path-id", report.Paths[0].PathID, "--public-key", public}
	for attempt := 0; attempt < 2; attempt++ {
		if e = json.Unmarshal([]byte(run(args...)), &view); e != nil {
			t.Fatal(e)
		}
		if view.Generation != 3 || len(view.Bindings) != 2 || view.Bindings[0].PublicKey != public {
			t.Fatal("CLI retry changed binding")
		}
	}
	if e = json.Unmarshal([]byte(run("controller", "relay", "status", "--config", controllerPath)), &status); e != nil {
		t.Fatal(e)
	}
	if status.RelayCatalog == nil || status.RelayCatalog.Generation != 3 {
		t.Fatal("CLI status is stale")
	}
}
