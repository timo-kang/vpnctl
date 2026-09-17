// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"bytes"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/atomicfile"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

func TestRegistryUncertainCommitKeepsDiskMemoryAndWGAligned(t *testing.T) {
	for _, operation := range []string{"register", "nat", "remove"} {
		t.Run(operation, func(t *testing.T) {
			cfg := config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24", WGApply: true, WGInterface: "wg-test", WGAddress: "10.7.0.1/24", WGPrivateKey: "private"}
			s, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			runner := &recordingWGRunner{}
			s.wg = wireguard.NewManager(runner)
			if _, err := s.registerNode(nodeRegistration{Name: "a", PubKey: "pub-a"}, true); err != nil {
				t.Fatal(err)
			}
			s.directOK["a"] = map[string]time.Time{"b": time.Now()}
			s.directOK["b"] = map[string]time.Time{"a": time.Now()}
			runner.configs = nil
			s.saveRegistry = func(path string, reg *store.Registry) error {
				if err := store.SaveRegistry(path, reg); err != nil {
					return err
				}
				return &atomicfile.CommitError{Err: syscall.EIO}
			}
			switch operation {
			case "register":
				_, err = s.registerNode(nodeRegistration{Name: "a", PubKey: "pub-next"}, true)
			case "remove":
				err = s.removeNode("a")
			case "nat":
				body, _ := json.Marshal(api.NATProbeRequest{NodeID: "a", PublicAddr: "127.0.0.1:1234", NATType: "full-cone"})
				rec := httptest.NewRecorder()
				s.handleNATProbe(rec, httptest.NewRequest(http.MethodPost, "/nat-probe", bytes.NewReader(body)))
				if rec.Code != 500 {
					t.Fatalf("uncertain NAT commit reported success: %d", rec.Code)
				}
			}
			if operation != "nat" && !atomicfile.Replaced(err) {
				t.Fatal(err)
			}
			disk, err := store.LoadRegistry(s.regPath)
			if err != nil {
				t.Fatal(err)
			}
			if !registriesEqual(disk, s.reg) {
				t.Fatalf("disk=%+v memory=%+v", disk, s.reg)
			}
			if operation == "nat" {
				if len(runner.configs) != 0 {
					t.Fatal("NAT applied WG")
				}
			} else {
				if len(runner.configs) != 1 {
					t.Fatalf("rollback after visible commit: %d applies", len(runner.configs))
				}
				if operation == "register" && !strings.Contains(runner.configs[0], "pub-next") {
					t.Fatal("WG kept old key")
				}
			}
			if operation == "remove" {
				if len(s.directOK) != 0 || len(s.reg.Nodes) != 0 {
					t.Fatal("removal left volatile state")
				}
				if strings.Contains(runner.configs[0], "pub-a") {
					t.Fatal("removed WG peer survived")
				}
				if err := s.removeNode("a"); err != nil {
					t.Fatal("removal retry", err)
				}
			}
			restarted, err := NewServer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !registriesEqual(restarted.reg, s.reg) {
				t.Fatal("restart changed committed state")
			}
		})
	}
}

func TestRegistryInitializationMigrationAndFailClosed(t *testing.T) {
	for _, body := range []string{"", "null\n", "{}\n", "updated_at: null\n", "nodes: []\nunknown: true\n", "version: 2\nnodes: []\n", "nodes: []\n---\nnodes: []\n"} {
		t.Run(body, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "registry.yaml")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewServer(config.ControllerConfig{DataDir: dir}); err == nil {
				t.Fatal("accepted corrupt registry")
			}
			got, _ := os.ReadFile(path)
			if string(got) != body {
				t.Fatal("rewrote invalid registry")
			}
		})
	}
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "legacy"}[legacy], func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.ControllerConfig{DataDir: dir}
			if legacy {
				if err := os.WriteFile(filepath.Join(dir, "registry.yaml"), []byte("nodes: []\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := NewServer(cfg); err != nil {
				t.Fatal(err)
			}
			if _, err := NewServer(cfg); err != nil {
				t.Fatal("restart", err)
			}
			if err := os.Remove(filepath.Join(dir, "registry.yaml")); err != nil {
				t.Fatal(err)
			}
			if _, err := NewServer(cfg); err == nil {
				t.Fatal("initialized empty registry loss accepted")
			}
		})
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "pki"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(config.ControllerConfig{DataDir: dir}); err == nil {
		t.Fatal("legacy PKI accepted missing registry")
	}
}

func registriesEqual(a, b *store.Registry) bool {
	x, _ := yaml.Marshal(a)
	y, _ := yaml.Marshal(b)
	return bytes.Equal(x, y)
}

func TestFleetStateSeparatesPendingEnrollmentAndLiveness(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		node store.NodeInfo
		want string
	}{
		{store.NodeInfo{EnrollmentPending: true, LastSeenAt: now}, "pending"},
		{store.NodeInfo{}, "enrolled"},
		{store.NodeInfo{PubKey: "key", LastSeenAt: now.Add(-time.Minute)}, "offline"},
		{store.NodeInfo{PubKey: "key", LastSeenAt: now}, "online"},
	} {
		if got := fleetNodeState(tc.node, now); got != tc.want {
			t.Errorf("got=%s want=%s", got, tc.want)
		}
	}
}
