//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relaycatalog"
)

// Real controller process, local authenticated admin IPC and enrolled mTLS clients.
// All secrets stay under private, never under the exported result directory.
type m3Controller struct {
	t                               *testing.T
	private, results, data, address string
	process                         *networkProcess
}

func newM3Controller(t *testing.T, ns, address, private, results string) *m3Controller {
	t.Helper()
	f := &m3Controller{t: t, private: private, results: results, data: filepath.Join(private, "controller"), address: address}
	_, public := wgKeyPair(t)
	cfg := config.Config{Controller: &config.ControllerConfig{
		Listen: address + ":9443", DataDir: f.data, VPNCIDR: "10.77.0.0/24",
		ServerPublicKey: public, ServerEndpoint: address + ":51819", ServerAllowedIPs: []string{"10.77.0.0/24"},
		PKI: &config.PKIConfig{CAExpiry: "24h", ServerExpiry: "2h", ClientExpiry: "1h", ServerRenewBefore: "30m", ClientRenewBefore: "10m", CheckInterval: "1s", CAOverlap: "1m", ServerSANs: []string{address}},
	}}
	path := filepath.Join(private, "controller.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	f.process = startNetworkProcess(t, ns, filepath.Join(private, "controller.log"), nil, integrationBinary(t), "controller", "init", "--config", path)
	eventually(t, 8*time.Second, "real controller IPC", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := api.Admin(ctx, f.data, api.AdminRequest{Operation: "pki.status"})
		return err
	})
	t.Cleanup(func() {
		// Controller logs contain a bootstrap token; export only redacted lines.
		b, _ := os.ReadFile(f.process.log)
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if strings.Contains(line, "token") {
				lines[i] = "[token log redacted]"
			}
		}
		if err := os.WriteFile(filepath.Join(results, "controller.log"), []byte(strings.Join(lines, "\n")), 0600); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *m3Controller) admin(req api.AdminRequest) api.AdminResponse {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := api.Admin(ctx, f.data, req)
	if err != nil {
		f.t.Fatalf("admin %s: %v", req.Operation, err)
	}
	return r
}
func (f *m3Controller) status() *relaycatalog.State {
	return f.admin(api.AdminRequest{Operation: "relay.catalog.status"}).RelayCatalog
}
func (f *m3Controller) apply(spec relaycatalog.Spec, ttl int) *relaycatalog.State {
	old := f.status()
	r := relaycatalog.Update{Spec: spec, TTLSeconds: ttl}
	if old != nil {
		r.ControllerID, r.ExpectedGeneration = old.ControllerID, old.Generation
	}
	return f.admin(api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &r}).RelayCatalog
}
func (f *m3Controller) grant(relay, principal string) {
	s := f.status()
	f.admin(api.AdminRequest{Operation: "relay.recipient.set", RelayRecipient: &relaycatalog.RecipientUpdate{ControllerID: s.ControllerID, ExpectedGeneration: s.Generation, RelayID: relay, PrincipalID: principal}})
}
func (f *m3Controller) enroll(ns, id string) string {
	f.t.Helper()
	key, public := wgKeyPair(f.t)
	path := filepath.Join(f.private, id+".yaml")
	cfg := config.Config{Node: &config.NodeConfig{Name: id, Controller: "https://" + f.address + ":9443", PKIDir: filepath.Join(f.private, id+"-pki"), WGPrivateKey: key, WGPublicKey: public}}
	if err := config.Save(path, cfg); err != nil {
		f.t.Fatal(err)
	}
	ca := filepath.Join(f.private, "bootstrap.crt")
	mustWrite(f.t, ca, f.admin(api.AdminRequest{Operation: "pki.status"}).PKI.CACert)
	token := f.admin(api.AdminRequest{Operation: "token.create", TTL: "10m"}).Token
	// Do not expose command arguments or raw bootstrap output on failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := netCommand(ctx, ns, integrationBinary(f.t), "node", "join", "--config", path, "--token", token, "--ca-cert", ca).Run(); err != nil {
		f.t.Fatal("identity enrollment failed", id, err)
	}
	if err := netCommand(ctx, ns, integrationBinary(f.t), "node", "join", "--config", path).Run(); err != nil {
		f.t.Fatal("identity registration failed", id, err)
	}
	return path
}

type m3SupervisorReport struct {
	ObservedAt        time.Time                    `json:"observed_at"`
	CycleMS           int64                        `json:"cycle_ms"`
	State             string                       `json:"state"`
	Reason            string                       `json:"reason"`
	Refresh           string                       `json:"refresh"`
	ApprovalValid     bool                         `json:"approval_valid"`
	ApprovalExpiresAt time.Time                    `json:"approval_expires_at"`
	Kernel            *relayapply.DeploymentResult `json:"kernel"`
}
type m3Recipient struct {
	t                                      *testing.T
	ns, config, relay, cache, key, results string
	watch                                  *networkProcess
	sequence                               int
	generation                             uint64
}

func (r *m3Recipient) args(action, endpoint string) []string {
	a := []string{integrationBinary(r.t), "relay", action, "--config", r.config, "--relay-id", r.relay, "--cache-dir", r.cache}
	if endpoint != "" {
		a = append(a, "--endpoint-id", endpoint)
	}
	return a
}
func (r *m3Recipient) call(action string, ep, port int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	return r.callContext(ctx, action, ep, port)
}
func (r *m3Recipient) callContext(ctx context.Context, action string, ep, port int, extra ...string) ([]byte, error) {
	a := r.args(action, "")
	if ep >= 0 {
		a = append(a, "--endpoint-id", fmt.Sprintf("ep%d", ep))
	}
	if action == "apply" {
		a = append(a, "--key-file", r.key, "--key-generation", fmt.Sprint(r.generation), "--listen-port", fmt.Sprint(port))
	}
	a = append(a, extra...)
	started := time.Now()
	b, err := netCommand(ctx, r.ns, a...).Output()
	var state map[string]any
	_ = json.Unmarshal(b, &state)
	class := "success"
	if err != nil {
		class = "failed"
		var exited *exec.ExitError
		if errors.As(err, &exited) && strings.Contains(string(exited.Stderr), "busy") {
			class = "busy"
		}
		if ctx.Err() != nil {
			class = "deadline"
		}
	}
	record, _ := json.Marshal(map[string]any{"at": time.Now().UTC(), "action": action, "endpoint": ep, "elapsed_ms": time.Since(started).Milliseconds(), "result": class, "state": state["state"], "reason": state["reason"]})
	file, saveErr := os.OpenFile(filepath.Join(r.results, r.relay+"-commands.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if saveErr != nil {
		return b, errors.Join(err, saveErr)
	}
	_, saveErr = file.Write(append(record, '\n'))
	return b, errors.Join(err, saveErr, file.Close())
}
func (r *m3Recipient) require(action string, ep, port int) relayapply.DeploymentResult {
	r.t.Helper()
	var out relayapply.DeploymentResult
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Explicit setup/recovery may wait for locks within its existing 15s
	// operation budget. Burst calls retain the default fail-fast behavior.
	// ready() independently verifies authenticated lease renewal.
	eventually(r.t, 15*time.Second, "relay "+action, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var options []string
		if action == "apply" || action == "release" || action == "recover" || action == "inspect" {
			deadline, _ := ctx.Deadline()
			remaining := time.Until(deadline)
			options = []string{"--lock-wait", min(5*time.Second, remaining).String(), "--timeout", remaining.String()}
		}
		b, err := r.callContext(ctx, action, ep, port, options...)
		if err != nil {
			var exited *exec.ExitError
			if errors.As(err, &exited) {
				return fmt.Errorf("%s: %w %s %s", action, err, b, exited.Stderr)
			}
			return fmt.Errorf("%s: %w %s", action, err, b)
		}
		if action == "refresh" {
			return nil
		}
		return json.Unmarshal(b, &out)
	})
	return out
}
func (r *m3Recipient) start(env ...string) {
	r.sequence++
	r.watch = startNetworkProcess(r.t, r.ns, filepath.Join(r.results, fmt.Sprintf("%s-supervise-%d.jsonl", r.relay, r.sequence)), env, append(r.args("supervise", ""), "--refresh-interval", "1s")...)
}
func (r *m3Recipient) ready() m3SupervisorReport {
	r.t.Helper()
	after := time.Now()
	var report m3SupervisorReport
	eventually(r.t, 12*time.Second, "authenticated supervisor "+r.relay, func() error {
		b, err := os.ReadFile(r.watch.log)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if err = json.Unmarshal([]byte(lines[len(lines)-1]), &report); err != nil {
			return err
		}
		if !report.ObservedAt.After(after) || report.Refresh != "success" || !report.ApprovalValid || report.Kernel == nil || !report.Kernel.KernelReady {
			return fmt.Errorf("not ready: %s", lines[len(lines)-1])
		}
		return nil
	})
	return report
}
