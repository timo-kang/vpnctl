package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDefaults_Node(t *testing.T) {
	t.Parallel()

	cfg := Config{Node: &NodeConfig{Name: "n1"}}
	ApplyDefaults(&cfg)

	if cfg.Node.WGInterface == "" || cfg.Node.WGConfigPath == "" {
		t.Fatalf("wg defaults not set: %+v", cfg.Node)
	}
	if cfg.Node.MTU != DefaultMTU {
		t.Fatalf("mtu=%d", cfg.Node.MTU)
	}
	if cfg.Node.ProbePort != DefaultProbePort {
		t.Fatalf("probe_port=%d", cfg.Node.ProbePort)
	}
	if cfg.Node.PolicyRoutingEnabled == nil || !*cfg.Node.PolicyRoutingEnabled {
		t.Fatalf("policy_routing_enabled default not true")
	}
}

func TestValidate_NodeRequiresControllerOrServerFields(t *testing.T) {
	t.Parallel()

	cfg := Config{Node: &NodeConfig{Name: "n1"}}
	ApplyDefaults(&cfg)
	if err := Validate(cfg); err == nil {
		t.Fatalf("expected error")
	}

	cfg.Node.Controller = "127.0.0.1:8080"
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestSave_Writes0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "node.yaml")
	cfg := Config{Node: &NodeConfig{Name: "n1", Controller: "127.0.0.1:8080"}}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}
