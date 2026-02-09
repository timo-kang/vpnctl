package store

import (
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
