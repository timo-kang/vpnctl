// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
)

func TestNetns_PKIRenewalDuringInitialRegisterFailure(t *testing.T) {
	requireNetwork(t)
	bin := integrationBinary(t)
	ns := newNamespaces(t, 1)
	dir := t.TempDir()
	ctrlPrivate, ctrlPublic := wgKeyPair(t)
	nodePrivate, nodePublic := wgKeyPair(t)
	ctrlDir := filepath.Join(dir, "controller")
	ctrlPath := filepath.Join(dir, "controller.yaml")
	cfg := config.Config{Controller: &config.ControllerConfig{Listen: "0.0.0.0:8443", DataDir: ctrlDir, VPNCIDR: "10.77.0.0/24", WGApply: true, WGAddress: "10.77.0.1/24", WGPrivateKey: ctrlPrivate, ServerPublicKey: ctrlPublic, ServerEndpoint: "192.0.2.1:51820", ServerAllowedIPs: []string{"10.77.0.0/24"}, PKI: &config.PKIConfig{CAExpiry: "1h", ServerExpiry: "1m", ClientExpiry: "8s", ClientRenewBefore: "5s", CheckInterval: "100ms", ServerSANs: []string{"192.0.2.1", "10.77.0.1"}}}}
	if err := config.Save(ctrlPath, cfg); err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(wrapperDir, 0700); err != nil {
		t.Fatal(err)
	}
	realWG, err := exec.LookPath("wg")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "fail-register")
	script := `#!/bin/sh
if [ -f "$VPNCTL_REGISTER_FAILURE" ]; then
 exit 1
fi
exec "$VPNCTL_REAL_WG" "$@"
`
	if err := os.WriteFile(filepath.Join(wrapperDir, "wg"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctrl := startNetworkProcess(t, ns[0], filepath.Join(dir, "controller.log"), []string{"PATH=" + wrapperDir + ":" + os.Getenv("PATH"), "VPNCTL_REAL_WG=" + realWG, "VPNCTL_REGISTER_FAILURE=" + marker}, bin, "controller", "init", "--config", ctrlPath)
	admin := func(req api.AdminRequest) (api.AdminResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return api.Admin(ctx, ctrlDir, req)
	}
	var status api.AdminResponse
	eventually(t, 5*time.Second, "PKI ready", func() error {
		var err error
		status, err = admin(api.AdminRequest{Operation: "pki.status"})
		return err
	})
	caPath := filepath.Join(dir, "ca.crt")
	mustWrite(t, caPath, status.PKI.CACert)
	token, err := admin(api.AdminRequest{Operation: "token.create", TTL: "1m"})
	if err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(dir, "node.yaml")
	disabled := false
	if err := config.Save(nodePath, config.Config{Node: &config.NodeConfig{Name: "node", Controller: "https://192.0.2.1:8443", PKIDir: filepath.Join(dir, "node-pki"), WGPrivateKey: nodePrivate, WGPublicKey: nodePublic, WGConfigPath: filepath.Join(dir, "wg.conf"), DirectMode: "off", KeepaliveIntervalSec: 1, PolicyRoutingEnabled: &disabled}}); err != nil {
		t.Fatal(err)
	}
	netOutput(t, ns[1], bin, "node", "join", "--config", nodePath, "--token", token.Token, "--ca-cert", caPath)
	netOutput(t, ns[1], bin, "node", "sync-config", "--config", nodePath)
	netOutput(t, ns[1], bin, "up", "--config", nodePath)
	nodeCfg, err := config.Load(nodePath)
	if err != nil {
		t.Fatal(err)
	}
	nodeCfg.Node.Controller = "https://10.77.0.1:8443"
	if err := config.Save(nodePath, nodeCfg); err != nil {
		t.Fatal(err)
	}
	initial, err := pki.LoadCredentials(nodeCfg.Node.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.ParseCertificate(initial.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(ctrlDir, "registry.yaml")
	before, err := store.LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, marker, "fail")
	nodeLog := filepath.Join(dir, "node.log")
	agent := startNetworkProcess(t, ns[1], nodeLog, nil, bin, "node", "serve", "--config", nodePath, "--retry-delay", "100ms", "--retry-max-delay", "200ms")
	time.Sleep(time.Until(leaf.NotAfter) + 500*time.Millisecond)
	current, err := pki.LoadCredentials(nodeCfg.Node.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := pki.ParseCertificate(current.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if current.ClientCert == initial.ClientCert || !renewed.NotAfter.After(time.Now()) {
		t.Fatal("certificate expired during initial registration failures")
	}
	log, err := os.ReadFile(nodeLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "sync-config failed") {
		t.Fatal("registration failure not exercised", string(log))
	}
	blocked, err := store.LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked.Nodes) != 1 || blocked.Nodes[0] != before.Nodes[0] {
		t.Fatal("failed registrations changed node state")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	released := time.Now()
	eventually(t, 5*time.Second, "same identity resumes over VPN", func() error {
		reg, err := store.LoadRegistry(registryPath)
		if err != nil {
			return err
		}
		if len(reg.Nodes) != 1 || reg.Nodes[0].VPNIP != nodeCfg.Node.VPNIP || reg.Nodes[0].PubKey != nodePublic {
			return fmt.Errorf("identity/lease changed")
		}
		if reg.Nodes[0].LastSeenAt.Before(released) {
			return fmt.Errorf("registration still blocked")
		}
		out := netOutput(t, ns[1], "ss", "-H", "-lun", "sport", "=", ":51900")
		if strings.TrimSpace(out) == "" {
			return fmt.Errorf("agent has not started")
		}
		return nil
	})
	if route := netOutput(t, ns[1], "ip", "route", "get", "10.77.0.1"); !strings.Contains(route, "dev wg0") {
		t.Fatal("controller bypassed WG", route)
	}
	agent.terminate(t)
	ctrl.terminate(t)
	t.Log("renewed beyond original 8s certificate lifetime during failed initial registration; same identity/lease recovered over WG")
}
