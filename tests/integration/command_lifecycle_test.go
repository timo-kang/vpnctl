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
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/controller"
	"vpnctl/internal/store"
)

// Run only inside the disposable container: a PATH-local wrapper applies the
// real WG mutation, then hangs once. No host executable/config is replaced.
func TestNetns_CommandTimeoutRollbackDuringShutdown(t *testing.T) {
	requireNetwork(t)
	ns := newNamespaces(t, 0)[0]
	bin := integrationBinary(t)
	dir := t.TempDir()
	realWG, err := exec.LookPath("wg")
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(wrapperDir, 0700); err != nil {
		t.Fatal(err)
	}
	wrapper := `#!/bin/sh
"$VPNCTL_REAL_WG" "$@" || exit $?
if [ "$1" = syncconf ] && [ -f "$VPNCTL_HANG_MARKER" ]; then
 rm "$VPNCTL_HANG_MARKER"
 : > "$VPNCTL_APPLIED_MARKER"
 sleep 60
fi
`
	if err := os.WriteFile(filepath.Join(wrapperDir, "wg"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	hang := filepath.Join(dir, "hang-once")
	applied := filepath.Join(dir, "applied")
	env := []string{"PATH=" + wrapperDir + ":" + os.Getenv("PATH"), "VPNCTL_REAL_WG=" + realWG, "VPNCTL_HANG_MARKER=" + hang, "VPNCTL_APPLIED_MARKER=" + applied}
	private, public := wgKeyPair(t)
	state := filepath.Join(dir, "state")
	path := filepath.Join(dir, "controller.yaml")
	cfg := config.Config{Controller: &config.ControllerConfig{Listen: "127.0.0.1:8080", DataDir: state, VPNCIDR: "10.77.0.0/24", WGApply: true, WGInterface: "wg0", WGAddress: "10.77.0.1/24", WGPrivateKey: private, ServerPublicKey: public, ProbePort: -1}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "controller.log")
	start := func() *networkProcess {
		p := startNetworkProcess(t, ns, log, env, bin, "controller", "init", "--config", path)
		eventually(t, 5*time.Second, "controller IPC", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := api.Admin(ctx, state, api.AdminRequest{Operation: "token.list"})
			// This focused WG test deliberately disables PKI. A structured rejection
			// proves IPC admission is ready, without creating any bootstrap token.
			if err != nil && strings.Contains(err.Error(), `409 Conflict: {"error":"PKI is not enabled"}`) {
				return nil
			}
			return err
		})
		return p
	}
	ctrl := start()
	testBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	register := func(name, key string, fail bool) *networkProcess {
		return startNetworkProcess(t, ns, filepath.Join(dir, name+".log"), []string{"VPNCTL_WORKER=register", "VPNCTL_REGISTER_NAME=" + name, "VPNCTL_REGISTER_KEY=" + key, fmt.Sprintf("VPNCTL_EXPECT_FAILURE=%d", map[bool]int{true: 1}[fail])}, testBin, "-test.run=^TestNetworkWorker$")
	}
	_, keyA := wgKeyPair(t)
	_, keyB := wgKeyPair(t)
	register("a", keyA, false).finish(t)
	before := netOutput(t, ns, "wg", "show", "wg0", "peers")
	if before != keyA {
		t.Fatal("baseline WG peer missing")
	}
	mustWrite(t, hang, "hang")
	request := register("b", keyB, true)
	eventually(t, 2*time.Second, "partial real WG application", func() error { _, err := os.Stat(applied); return err })
	peers := netOutput(t, ns, "wg", "show", "wg0", "peers")
	if !strings.Contains(peers, keyB) {
		t.Fatal("fault did not partially apply WG")
	}
	registry := func(want int) {
		t.Helper()
		reg, err := store.LoadRegistry(filepath.Join(state, "registry.yaml"))
		if err != nil || len(reg.Nodes) != want {
			t.Fatalf("registry want %d: %v", want, err)
		}
	}
	registry(1)
	if err := ctrl.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Ownership cannot transfer while an accepted command may still mutate WG.
	if lock, err := controller.AcquireStateLock(state); err == nil {
		lock.Close()
		t.Fatal("ownership transferred before rollback")
	}
	request.finishWithin(t, 8*time.Second)
	ctrl.finishWithin(t, 3*time.Second)
	registry(1)
	if netOutput(t, ns, "wg", "show", "wg0", "peers") != before {
		t.Fatal("real WG state did not rollback")
	}
	lock, err := controller.AcquireStateLock(state)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	ctrl = start()
	register("b", keyB, false).finish(t)
	registry(2)
	if !strings.Contains(netOutput(t, ns, "wg", "show", "wg0", "peers"), keyB) {
		t.Fatal("next mutation failed")
	}
	ctrl.terminate(t)
	t.Log("partial real WG apply timed out; SIGTERM drained rollback; registry and kernel restored; restart accepted next mutation")
}
