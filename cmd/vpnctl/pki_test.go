// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
)

func TestPKICLITrustedBootstrapBackupAndRestore(t *testing.T) {
	dir, err := os.MkdirTemp("", "vpnctl-pki-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	controllerPath := filepath.Join(dir, "controller.yaml")
	body := fmt.Sprintf("controller:\n  listen: %q\n  data_dir: %q\n  vpn_cidr: 10.7.0.0/24\n  wg_address: 10.7.0.1/24\n  probe_port: -1\n  pki: {}\n", address, filepath.Join(dir, "controller"))
	if err := os.WriteFile(controllerPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	process := cliProcess(t, "controller", "init", "--config", controllerPath)
	log, err := os.Create(filepath.Join(dir, "controller.log"))
	if err != nil {
		t.Fatal(err)
	}
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { process.Process.Kill(); process.Wait(); log.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := api.Admin(context.Background(), filepath.Join(dir, "controller"), api.AdminRequest{Operation: "pki.status"}); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := cliProcess(t, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("CLI error: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	trust := run("controller", "pki", "trust", "--config", controllerPath)
	trustedPath := filepath.Join(dir, "trusted-ca.pem")
	if err := os.WriteFile(trustedPath, []byte(trust+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	token := run("controller", "token", "create", "--config", controllerPath, "--single-use")
	nodePath := filepath.Join(dir, "node.yaml")
	nodeDir := filepath.Join(dir, "node-pki")
	if err := os.WriteFile(nodePath, []byte(fmt.Sprintf("node:\n  name: a\n  controller: %q\n  pki_dir: %q\n", address, nodeDir)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cliProcess(t, "node", "join", "--config", nodePath, "--token", token).CombinedOutput(); err == nil {
		t.Fatal("bootstrap accepted without pinned CA")
	}
	wrongCA := filepath.Join(dir, "wrong-ca.pem")
	if err := pki.GenerateCA(filepath.Join(dir, "wrong-ca.key"), wrongCA, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := cliProcess(t, "node", "join", "--config", nodePath, "--token", token, "--ca-cert", wrongCA).CombinedOutput(); err == nil {
		t.Fatal("bootstrap accepted wrong CA")
	}
	run("node", "join", "--config", nodePath, "--token", token, "--ca-cert", trustedPath)
	credentials, err := pki.LoadCredentials(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.ValidateForInstall("a"); err != nil {
		t.Fatal(err)
	}
	client := api.NewCredentialClient(address, nodeDir)
	defer client.CloseIdleConnections()
	if err := client.SyncCredentials(context.Background(), nodeDir, "a"); err != nil {
		t.Fatal(err)
	}
	run("controller", "pki", "ca-prepare", "--config", controllerPath)
	if out, err := cliProcess(t, "controller", "pki", "ca-activate", "--config", controllerPath).CombinedOutput(); err == nil || !strings.Contains(string(out), "acknowledged") {
		t.Fatalf("missing meaningful CA gate error: %v %s", err, out)
	}
	if err := client.SyncCredentials(context.Background(), nodeDir, "a"); err != nil {
		t.Fatal(err)
	}
	run("controller", "pki", "ca-activate", "--config", controllerPath)
	if err := client.SyncCredentials(context.Background(), nodeDir, "a"); err != nil {
		t.Fatal(err)
	}
	run("controller", "pki", "ca-rollback", "--config", controllerPath)
	if err := client.SyncCredentials(context.Background(), nodeDir, "a"); err != nil {
		t.Fatal(err)
	}
	current, err := pki.LoadCredentials(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(current.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	run("controller", "pki", "revoke", "--config", controllerPath, "--fingerprint", pki.Fingerprint(cert))
	if _, err := client.FleetStatus(context.Background()); err == nil {
		t.Fatal("CLI revocation did not take effect")
	}
	backupPath := filepath.Join(dir, "backup.json")
	run("controller", "pki", "backup", "--config", controllerPath, "--out", backupPath)
	info, err := os.Stat(backupPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup permissions")
	}
	restoredDir := filepath.Join(dir, "restored")
	restoredConfig := filepath.Join(dir, "restored.yaml")
	run("controller", "pki", "restore", "--file", backupPath, "--data-dir", restoredDir, "--config-out", restoredConfig)
	stateData, err := os.ReadFile(filepath.Join(restoredDir, "pki", "authority.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.ValidateAuthoritySnapshot(stateData); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Phase        string                           `json:"phase"`
		Certificates map[string]pki.CertificateRecord `json:"certificates"`
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "rollback" || state.Certificates[pki.Fingerprint(cert)].RevokedAt.IsZero() {
		t.Fatal("restore lost CA transition or revocation")
	}
}
