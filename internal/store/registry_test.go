// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRegistry_MissingFile_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "registry.yaml")
	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if reg == nil {
		t.Fatalf("registry is nil")
	}
	if len(reg.Nodes) != 0 {
		t.Fatalf("nodes=%d", len(reg.Nodes))
	}
}

func TestSaveRegistry_RoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "registry.yaml")

	in := &Registry{Nodes: []NodeInfo{{ID: "1", Name: "n1", VPNIP: "10.7.0.2/32"}}}
	if err := SaveRegistry(path, in); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}

	out, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(out.Nodes) != 1 {
		t.Fatalf("nodes=%d", len(out.Nodes))
	}
	if out.Nodes[0].Name != "n1" || out.Nodes[0].VPNIP != "10.7.0.2/32" {
		t.Fatalf("node=%+v", out.Nodes[0])
	}
	if out.UpdatedAt.IsZero() {
		t.Fatalf("updated_at not set")
	}
}

func TestRemoveNodeSaveFailureDoesNotMutateLoadedRegistry(t *testing.T) {
	t.Parallel()

	loaded := &Registry{Nodes: []NodeInfo{
		{ID: "node-a", Name: "node-a"},
		{ID: "node-b", Name: "node-b"},
	}}
	injected := errors.New("injected rename failure")
	found, err := removeNode(
		"/registry.yaml",
		"node-a",
		func(string) (*Registry, error) { return loaded, nil },
		func(string, *Registry) error { return injected },
	)
	if !found {
		t.Fatal("expected node to be found")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v, want %v", err, injected)
	}
	if len(loaded.Nodes) != 2 || loaded.Nodes[0].Name != "node-a" {
		t.Fatalf("failed removal mutated loaded registry: %+v", loaded.Nodes)
	}
}

func TestRemoveNodePersistsReplacement(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "registry.yaml")
	original := &Registry{Nodes: []NodeInfo{
		{ID: "node-a", Name: "node-a"},
		{ID: "node-b", Name: "node-b"},
	}}
	if err := SaveRegistry(path, original); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}

	found, err := RemoveNode(path, "node-a")
	if err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if !found {
		t.Fatal("expected node to be found")
	}
	persisted, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(persisted.Nodes) != 1 || persisted.Nodes[0].Name != "node-b" {
		t.Fatalf("persisted nodes=%+v", persisted.Nodes)
	}
}
