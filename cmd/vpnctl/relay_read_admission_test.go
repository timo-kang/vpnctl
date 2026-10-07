// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

func TestNodeRelayReadAdmission(t *testing.T) {
	for _, command := range []string{"plan", "status"} {
		for _, mode := range []string{"latest-rejection", "expires-while-queued", "cancel", "deadline", "missing"} {
			t.Run(command+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				cacheDir := filepath.Join(dir, "cache")
				cfg := config.Config{Node: &config.NodeConfig{Name: "robot-a", Controller: "https://unused.invalid", PKIDir: dir, RelayCacheDir: cacheDir}}
				path := filepath.Join(dir, "node.yaml")
				if err := config.Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				var holder *relaycache.Store
				var issuer *cliPlanIssuer
				if mode != "missing" {
					var err error
					holder, err = relaycache.Open(cacheDir, relaycache.Options{NodeID: "robot-a", Create: true})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { holder.Close() })
					spec, err := readRelaySpec("../../configs/relay-catalog.example.json")
					if err != nil {
						t.Fatal(err)
					}
					env := relaycatalog.Environment{Nodes: map[string]bool{"robot-a": true}, VPNCIDR: "10.7.0.0/24"}
					at, ttl := time.Now().UTC(), 3600
					if mode == "expires-while-queued" {
						at, ttl = at.Add(-63*time.Second), 65
					}
					state, err := relaycatalog.Apply(nil, relaycatalog.Update{Spec: spec, TTLSeconds: ttl}, env, at)
					if err != nil {
						t.Fatal(err)
					}
					issuer = &cliPlanIssuer{state: state, env: env}
					if _, err = holder.Refresh(context.Background(), issuer); err != nil {
						t.Fatal(err)
					}
				}
				timeout := "3s"
				if mode == "deadline" {
					timeout = "80ms"
				}
				cmd := cliProcess(t, "node", "relay", command, "--config", path, "--timeout", timeout)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				started := time.Now()
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				if mode == "latest-rejection" || mode == "expires-while-queued" || mode == "cancel" {
					// Observe a live admission ticket before changing the approval. The
					// waiting reader must acquire the current rejection, never its old cache.
					deadline := time.Now().Add(2 * time.Second)
					queued := false
					for !queued && time.Now().Before(deadline) {
						files, _ := filepath.Glob(filepath.Join(cacheDir, "admission-??"))
						for _, path := range files {
							file, err := os.OpenFile(path, os.O_RDWR, 0)
							if err != nil {
								t.Fatal(err)
							}
							err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
							file.Close()
							if errors.Is(err, syscall.EWOULDBLOCK) {
								queued = true
								break
							}
							if err != nil {
								t.Fatal(err)
							}
						}
						if !queued {
							time.Sleep(5 * time.Millisecond)
						}
					}
					if !queued {
						t.Fatal("reader did not join admission queue")
					}
					select {
					case err := <-done:
						t.Fatal("reader bypassed held cache", err)
					default:
					}
					switch mode {
					case "latest-rejection":
						issuer.getError = &api.HTTPError{StatusCode: 403}
						if _, err := holder.Refresh(context.Background(), issuer); err == nil {
							t.Fatal("rejection missing")
						}
					case "expires-while-queued":
						time.Sleep(time.Until(issuer.state.ExpiresAt) + 20*time.Millisecond)
					case "cancel":
						if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
							t.Fatal(err)
						}
					}
					if mode != "cancel" {
						if err := holder.Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
				var err error
				select {
				case err = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("reader exceeded bounded admission")
				}
				if mode == "deadline" {
					if err == nil || !strings.Contains(stderr.String(), "context deadline exceeded") || stdout.Len() != 0 || time.Since(started) > 2*time.Second {
						t.Fatalf("read did not honor total deadline: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
					}
					return
				}
				if mode == "cancel" {
					if err == nil || !strings.Contains(stderr.String(), "context canceled") || stdout.Len() != 0 {
						t.Fatalf("canceled reader emitted approval: %v %s %s", err, stdout.String(), stderr.String())
					}
					return
				}
				if (command == "plan") != (err != nil) {
					t.Fatalf("unexpected read exit: %v %s", err, stderr.String())
				}
				var report struct {
					Validity      string `json:"validity"`
					BlockedReason string `json:"blocked_reason"`
					State         string `json:"state"`
					Reason        string `json:"reason"`
				}
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err, stdout.String(), stderr.String())
				}
				if mode == "missing" {
					if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
						t.Fatal("read created missing cache", err)
					}
					if command == "status" && report.Validity != "missing" || command == "plan" && report.Reason != "cache_missing" {
						t.Fatal("missing cache misreported", report)
					}
				} else if mode == "expires-while-queued" {
					if command == "status" && report.Validity != "expired" || command == "plan" && (report.State != "blocked" || report.Reason != "cache_expired") {
						t.Fatal("waiting extended approval lifetime", report)
					}
				} else if command == "status" && report.BlockedReason != "identity_denied" || command == "plan" && (report.State != "blocked" || report.Reason != "cache_identity_denied") {
					t.Fatal("queued read lost current rejection", report)
				}
			})
		}
	}
}
