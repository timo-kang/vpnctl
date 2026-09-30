// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"vpnctl/internal/relaycatalog"
)

func TestRelayCatalogRegistryVersion(t *testing.T) {
	catalog, e := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24"}}, relaycatalog.Environment{}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "registry.yaml")
	reg := &Registry{RelayCatalog: catalog}
	if e = SaveRegistry(path, reg); e != nil {
		t.Fatal(e)
	}
	read, e := LoadRegistry(path)
	if e != nil || read.Version != 2 || read.RelayCatalog.ControllerID != catalog.ControllerID {
		t.Fatal("catalog round trip", e)
	}
	read.RelayCatalog = nil
	if e = SaveRegistry(path, read); e == nil {
		t.Fatal("catalog silently dropped")
	}
	for _, raw := range []string{"version: 2\nnodes: []\n", "version: 1\nnodes: []\nrelay_catalog: {}\n", "version: 3\nnodes: []\nrelay_catalog: {}\n"} {
		if e = os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = LoadRegistry(path); e == nil {
			t.Fatal("version mismatch accepted", raw)
		}
	}
}

func TestRelayRecipientRegistryVersion(t *testing.T) {
	catalog, e := relaycatalog.Apply(nil, relaycatalog.Update{TTLSeconds: 3600, Spec: relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24"}}, relaycatalog.Environment{}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	catalog.RecipientSchema = 1 // Sticky even when the last grant was withdrawn.
	reg := &Registry{Version: 2, RelayCatalog: catalog}
	path := filepath.Join(t.TempDir(), "registry.yaml")
	if e = SaveRegistry(path, reg); e != nil {
		t.Fatal(e)
	}
	loaded, e := LoadRegistry(path)
	if e != nil || loaded.Version != 3 || loaded.RelayCatalog.RecipientSchema != 1 {
		t.Fatal("version 3 roundtrip", e)
	}
	loaded.RelayCatalog.RecipientSchema = 0
	if e = SaveRegistry(path, loaded); e == nil {
		t.Fatal("version 3 downgraded")
	}
	reg.Version = 4
	if e = SaveRegistry(path, reg); e == nil {
		t.Fatal("future registry overwritten as version 3")
	}
	for _, raw := range []string{
		"version: 2\nnodes: []\nrelay_catalog:\n  recipient_schema: 1\n",
		"version: 3\nnodes: []\nrelay_catalog:\n  recipient_schema: 9\n",
		"version: 2\nnodes: []\nrelay_catalog:\n  recipients: [{relay_id: r, principal_id: p}]\n",
		"version: 4\nnodes: []\n",
	} {
		if e = os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = LoadRegistry(path); e == nil {
			t.Fatal("invalid version accepted")
		}
	}
}
