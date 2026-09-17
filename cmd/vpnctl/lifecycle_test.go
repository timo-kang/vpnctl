package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/controller"
)

func TestControllerSignalsDrainAndAllowRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "vpnctl-signal-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	configPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("controller:\n  listen: 127.0.0.1:0\n  data_dir: %q\n  vpn_cidr: 10.7.0.0/24\n  wg_address: 10.7.0.1/24\n  probe_port: -1\n  pki: {}\n", dir)
	if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for _, signal := range []os.Signal{syscall.SIGTERM, os.Interrupt, syscall.SIGTERM} {
		cmd := cliProcess(t, "controller", "init", "--config", configPath)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := api.Admin(ctx, dir, api.AdminRequest{Operation: "token.list"})
			cancel()
			if err == nil {
				ready = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("controller did not start")
		}
		if err := cmd.Process.Signal(signal); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("signal %v failed graceful exit: %v", signal, err)
			}
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("graceful exit timed out")
		}
		if _, err := os.Stat(api.AdminSocketPath(dir)); !os.IsNotExist(err) {
			t.Fatalf("IPC socket survived shutdown: %v", err)
		}
		lock, err := controller.AcquireStateLock(dir)
		if err != nil {
			t.Fatal("state ownership leaked", err)
		}
		lock.Close()
	}
}
