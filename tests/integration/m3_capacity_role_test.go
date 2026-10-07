//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The outer VM quota measures all colocated roles. This distinct profile limits
// just the live robot supervisor and both actuators, including command children.
// Initial enrollment/preparation, controller, relays and measurement stay outside.
func TestVMApplicationCapacity(t *testing.T) {
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		t.Skip("requires disposable VM runner")
	}
	requireIsolatedGuest(t)
	cpu := os.Getenv("VPNCTL_CAPACITY_ROBOT_CPU")
	paths, err := strconv.Atoi(os.Getenv("VPNCTL_CAPACITY_PATHS"))
	if err != nil || paths != 4 && paths != 8 || capacityQuota(cpu) == "" {
		t.Fatal("explicit robot CPU and 4/8 candidate profile required")
	}
	for _, healthy := range []int{0, paths/2 - 1, paths - 1} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			applicationMixedCandidatesProfile(t, healthy, false, paths, cpu)
		})
	}
}

type capacityGroup struct {
	file  *os.File
	path  string
	quota string
	model string
}

func capacityQuota(cpu string) string {
	switch cpu {
	case "1":
		return "100000 100000"
	case "0.5":
		return "50000 100000"
	case "0.25":
		return "25000 100000"
	}
	return ""
}

func newCapacityGroup(t *testing.T, cpu string) *capacityGroup {
	t.Helper()
	requireIsolatedGuest(t) // Check before the first filesystem mutation.
	quota := capacityQuota(cpu)
	if quota == "" {
		t.Fatal("unsupported CPU profile")
	}
	const root = "/sys/fs/cgroup"
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil || !strings.Contains(" "+strings.TrimSpace(string(controllers))+" ", " cpu ") {
		t.Fatal("guest CPU controller unavailable", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+cpu"), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp(root, "vpnctl-capacity-")
	if err != nil {
		t.Fatal(err)
	}
	g := &capacityGroup{path: path, quota: quota}
	t.Cleanup(func() {
		if g.file != nil {
			g.file.Close()
		}
		// Kill only descendants of this invocation's newly created group.
		// A command child can still be exiting after its parent was reaped.
		if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0600); err != nil {
			t.Error("role cgroup cleanup", err)
		}
		until := time.Now().Add(3 * time.Second)
		for {
			err := os.Remove(path)
			if err == nil {
				return
			}
			if time.Now().After(until) {
				t.Error("role cgroup removal", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	if err := os.WriteFile(filepath.Join(path, "cpu.max"), []byte(quota), 0600); err != nil {
		t.Fatal(err)
	}
	g.file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		t.Fatal("guest CPU identity", err)
	}
	for _, line := range strings.Split(string(cpuInfo), "\n") {
		key, value, _ := strings.Cut(line, ":")
		if strings.TrimSpace(key) == "model name" {
			g.model = strings.TrimSpace(value)
			break
		}
	}
	if g.model == "" {
		t.Fatal("guest CPU model unavailable")
	}
	return g
}

func (g *capacityGroup) requireMembership(t *testing.T, pid int, member bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	want := "0::/" + filepath.Base(g.path)
	if err != nil || (strings.TrimSpace(string(b)) == want) != member {
		t.Fatal("incorrect resource role placement", pid, member, err)
	}
}

func (g *capacityGroup) evidence(t *testing.T) map[string]any {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(g.path, name))
		if err != nil {
			t.Fatal("missing role resource evidence", name, err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read("cpu.max"); got != g.quota {
		t.Fatal("CPU profile changed", got)
	}
	return map[string]any{"scope": "robot-supervisor-and-two-actuators", "cpu_max": g.quota,
		"cpu_model": g.model, "guest_vcpus": runtime.NumCPU(),
		"cpu_stat": read("cpu.stat"), "cpu_pressure": read("cpu.pressure"),
		"initial_preparation_limited": false, "controller_relay_measurement_limited": false}
}
