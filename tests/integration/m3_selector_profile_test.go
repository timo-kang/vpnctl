//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Optional diagnostics never fail or prolong the qualification. The actual
// app2 producer creates this private directory before its first receipt.
func capacitySelectorProfile(results string, report map[string]any) ([]string, func(int)) {
	off := []string{"VPNCTL_SELECTOR_PROFILE_DIR="}
	if os.Getenv("VPNCTL_CAPACITY_SELECTOR_PROFILE") != "1" {
		return off, func(int) {}
	}
	evidence := map[string]any{"requested": true, "status": "not_triggered", "role": "app2", "requested_duration_ns": int64(8_000_000_000)}
	report["selector_profile"] = evidence
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		evidence["status"] = "not_vm_worker"
		return off, func(int) {}
	}
	directory := filepath.Join(results, "selector-profile-app2")
	return []string{"VPNCTL_SELECTOR_PROFILE_DIR=" + directory}, func(pid int) {
		evidence["producer_pid"] = pid
		evidence["trigger_before_monotonic_ns"] = profileMonotonic()
		defer func() { evidence["trigger_after_monotonic_ns"] = profileMonotonic() }()
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			evidence["status"] = "directory_unavailable"
			return
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			evidence["status"] = "directory_unavailable"
			return
		}
		defer root.Close()
		opened, err := root.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			evidence["status"] = "directory_changed"
			return
		}
		f, err := root.OpenFile("start", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			evidence["status"] = "trigger_unavailable"
			return
		}
		if err := f.Close(); err != nil {
			evidence["status"] = "trigger_unavailable"
			return
		}
		evidence["status"] = "triggered"
	}
}

func profileMonotonic() int64 {
	var stamp unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp) != nil {
		return 0
	}
	return stamp.Nano()
}

func TestCapacitySelectorProfileOptionalAndExclusive(t *testing.T) {
	t.Setenv("VPNCTL_SELECTOR_PROFILE_DIR", "/inherited-must-not-enable")
	t.Setenv("VPNCTL_CAPACITY_SELECTOR_PROFILE", "0")
	report := map[string]any{}
	env, trigger := capacitySelectorProfile(t.TempDir(), report)
	trigger(123)
	if len(env) != 1 || env[0] != "VPNCTL_SELECTOR_PROFILE_DIR=" || len(report) != 0 {
		t.Fatal("disabled mode changed report or inherited profiler")
	}
	t.Setenv("VPNCTL_CAPACITY_SELECTOR_PROFILE", "1")
	t.Setenv("VPNCTL_VM_WORKER", "1")
	dir := t.TempDir()
	env, trigger = capacitySelectorProfile(dir, report)
	profileDir := filepath.Join(dir, "selector-profile-app2")
	if env[0] != "VPNCTL_SELECTOR_PROFILE_DIR="+profileDir {
		t.Fatal("wrong producer environment")
	}
	trigger(123)
	evidence := report["selector_profile"].(map[string]any)
	if evidence["status"] != "directory_unavailable" {
		t.Fatal("missing profiler treated as success")
	}
	os.Mkdir(profileDir, 0700)
	trigger(123)
	if evidence["status"] != "triggered" || evidence["producer_pid"] != 123 {
		t.Fatal("trigger missing", evidence)
	}
	if info, err := os.Stat(filepath.Join(profileDir, "start")); err != nil || info.Size() != 0 || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe trigger")
	}
	trigger(123)
	if evidence["status"] != "trigger_unavailable" {
		t.Fatal("trigger overwritten")
	}
}

func TestCapacitySelectorProfileRejectsNonWorkerAndSymlink(t *testing.T) {
	t.Setenv("VPNCTL_CAPACITY_SELECTOR_PROFILE", "1")
	t.Setenv("VPNCTL_VM_WORKER", "0")
	report := map[string]any{}
	env, trigger := capacitySelectorProfile(t.TempDir(), report)
	trigger(123)
	if env[0] != "VPNCTL_SELECTOR_PROFILE_DIR=" || report["selector_profile"].(map[string]any)["status"] != "not_vm_worker" {
		t.Fatal("non-VM enabled")
	}
	t.Setenv("VPNCTL_VM_WORKER", "1")
	dir, other := t.TempDir(), t.TempDir()
	os.Symlink(other, filepath.Join(dir, "selector-profile-app2"))
	_, trigger = capacitySelectorProfile(dir, report)
	trigger(123)
	if _, err := os.Stat(filepath.Join(other, "start")); !os.IsNotExist(err) {
		t.Fatal("followed symlink")
	}
}
