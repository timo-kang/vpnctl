// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vpnctl/internal/config"
)

func TestNodeServeRestoresCachedPathAndRetriesRequestTimeout(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "tunnel-ready")
	// Command shims keep this supervisor test unprivileged; the netns suite
	// separately verifies the actual kernel interface, routing and packets.
	for _, name := range []string{"ip", "wg"} {
		script := "#!/bin/sh\n"
		if name == "wg" {
			script += "if [ \"$1\" = syncconf ]; then : > \"$VPNCTL_TEST_TUNNEL_READY\"; fi\n"
		}
		script += "exit 0\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var requests atomic.Int32
	reached := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.URL.Path != "/register" {
			http.Error(w, "unexpected request", 400)
			return
		}
		if _, err := os.Stat(marker); err != nil {
			t.Error("controller request preceded cached WireGuard restoration")
		}
		if requests.Add(1) == 1 {
			// Exceed the API client's real request timeout. The supervisor must
			// retry while its process context is still alive.
			<-r.Context().Done()
			return
		}
		select {
		case reached <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"node_id":"test","vpn_ip":"10.77.0.2/32"}`)
	}))
	defer server.Close()
	disabled := false
	cfg := config.Config{Node: &config.NodeConfig{
		Name: "test", Controller: server.URL, WGPrivateKey: "test-private", WGPublicKey: "test-public", VPNIP: "10.77.0.2/32",
		ServerPublicKey: "server-public", ServerEndpoint: "192.0.2.1:51820", ServerAllowedIPs: []string{"10.77.0.0/24"},
		WGConfigPath: filepath.Join(dir, "wg.conf"), DirectMode: "off", PolicyRoutingEnabled: &disabled,
	}}
	path := filepath.Join(dir, "node.yaml")
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cmd := cliProcess(t, "node", "serve", "--config", path, "--retry-delay", "10ms", "--retry-max-delay", "20ms")
	cmd.Env = append(cmd.Env, "PATH="+dir+":"+os.Getenv("PATH"), "VPNCTL_TEST_TUNNEL_READY="+marker)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	select {
	case <-reached:
	case <-time.After(15 * time.Second):
		t.Fatal("node serve stopped or failed to retry after a request timeout")
	}
}
