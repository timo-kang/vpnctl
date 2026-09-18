package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMonitorCLIStartupErrors(t *testing.T) {
	for _, tc := range []struct{ name, ip, wg, want string }{
		{"missing_interface", "echo 'device missing' >&2; exit 1", "exit 0", "interface wg0 exists"},
		{"backend", "echo 'inet 10.0.0.1/24'", "echo 'not a WireGuard interface' >&2; exit 1", "Tailscale and Nebula"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"ip": tc.ip, "wg": tc.wg} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := cliProcess(t, "monitor", "--interface", "wg0", "--watch", "--data", filepath.Join(dir, "monitor.db"))
			cmd.Env = append(cmd.Env, "PATH="+dir)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatal(err, string(out))
			}
		})
	}
}

func TestMonitorCLIMetricsBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	for name, body := range map[string]string{"ip": "echo 'inet 10.0.0.1/24'", "wg": "printf 'private\\tpublic\\t51820\\toff\\n'"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := cliProcess(t, "monitor", "--interface", "wg0", "--watch", "--data", filepath.Join(dir, "monitor.db"), "--metrics-port", strconv.Itoa(port))
	cmd.Env = append(cmd.Env, "PATH="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "metrics bind") {
		t.Fatal(err, string(out))
	}
}
