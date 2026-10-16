//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Child process emits final evidence only on SIGTERM, like both real apps.
// It never accesses a network namespace, device, socket, or privileged command.
func TestAppVMDrainHelper(t *testing.T) {
	mode := os.Getenv("VPNCTL_APP_DRAIN_HELPER")
	if mode == "" {
		return
	}
	signals := make(chan os.Signal, 1)
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(signals, syscall.SIGTERM)
	}
	if err := os.WriteFile(os.Getenv("VPNCTL_APP_DRAIN_READY"), []byte("ready"), 0600); err != nil {
		os.Exit(3)
	}
	if mode == "ignore" {
		for {
			time.Sleep(time.Hour)
		}
	}
	<-signals
	if mode == "failed" {
		os.Exit(2)
	}
	fmt.Println(`{"payload":{"events":[{"failure":"read","outcome_unknown":true}]}}`)
	os.Exit(0)
}

func appVMDrainProcess(t *testing.T, mode string) *networkProcess {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "client.json")
	file, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAppVMDrainHelper$")
	ready := filepath.Join(dir, "ready")
	cmd.Env = append(os.Environ(), "VPNCTL_APP_DRAIN_HELPER="+mode, "VPNCTL_APP_DRAIN_READY="+ready, "GORACE=atexit_sleep_ms=0")
	cmd.Stdout, cmd.Stderr = file, file
	if err := cmd.Start(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	p := &networkProcess{cmd: cmd, log: log}
	t.Cleanup(p.stop)
	eventually(t, 3*time.Second, "unprivileged helper ready", func() error { _, err := os.Stat(ready); return err })
	return p
}

func TestAppVMFailureDrainPreservesFinalEvents(t *testing.T) {
	p := appVMDrainProcess(t, "report")
	if state := drainAppVMClient(p, 2*time.Second); state != "drained" {
		t.Fatalf("final evidence not drained: %s", state)
	}
	b, err := os.ReadFile(p.log)
	var report struct {
		Payload struct {
			Events []struct {
				Failure string `json:"failure"`
			} `json:"events"`
		} `json:"payload"`
	}
	if err != nil || json.Unmarshal(b, &report) != nil || len(report.Payload.Events) != 1 || report.Payload.Events[0].Failure != "read" {
		t.Fatal("failed operation evidence lost during cleanup")
	}
	if !p.stopped || p.cmd.ProcessState == nil || !p.cmd.ProcessState.Exited() {
		t.Fatal("client not joined")
	}
	if state := drainAppVMClient(p, time.Second); state != "already_stopped" {
		t.Fatal("drained client signalled twice")
	}
}

func TestAppVMFailureDrainDoesNotStrandOtherClient(t *testing.T) {
	first, second := appVMDrainProcess(t, "ignore"), appVMDrainProcess(t, "report")
	started := time.Now()
	if state := drainAppVMClient(first, 50*time.Millisecond); state != "forced" {
		t.Fatalf("unresponsive client: %s", state)
	}
	if time.Since(started) > 3*time.Second || !first.stopped || first.cmd.ProcessState == nil {
		t.Fatal("forced cleanup did not join within bound")
	}
	if state := drainAppVMClient(second, 2*time.Second); state != "drained" {
		t.Fatal("first cleanup failure prevented independent evidence")
	}
}

func TestAppVMFailureDrainRetainsExitFailure(t *testing.T) {
	p := appVMDrainProcess(t, "failed")
	if state := drainAppVMClient(p, 2*time.Second); state != "failed" {
		t.Fatalf("nonzero child exit erased: %s", state)
	}
	if p.cmd.ProcessState == nil || p.cmd.ProcessState.ExitCode() != 2 {
		t.Fatal("original client exit not retained")
	}
}
