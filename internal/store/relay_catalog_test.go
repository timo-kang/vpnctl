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
