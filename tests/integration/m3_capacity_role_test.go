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
// Initial enrollment/preparation, controller, relays and measurement stay outside
// the robot quota. The opt-in split layout also gives these roles guest CPU 1.
func TestVMApplicationCapacity(t *testing.T) {
	if os.Getenv("VPNCTL_VM_WORKER") != "1" {
		t.Skip("requires disposable VM runner")
	}
	requireIsolatedGuest(t)
	cpu := os.Getenv("VPNCTL_CAPACITY_ROBOT_CPU")
	rebuild := os.Getenv("VPNCTL_CAPACITY_REBUILD")
	if rebuild != "0" && rebuild != "1" {
		t.Fatal("explicit steady or rebuild profile required")
	}
	layout := os.Getenv("VPNCTL_CAPACITY_CPU_LAYOUT")
	if layout != "shared" && layout != "split" {
		t.Fatal("explicit CPU layout required")
	}
	wantCPUs := 1
	if layout == "split" {
		wantCPUs = 2
	}
	if runtime.NumCPU() != wantCPUs {
		t.Fatal("incorrect guest CPU count", runtime.NumCPU(), wantCPUs)
	}
	paths, err := strconv.Atoi(os.Getenv("VPNCTL_CAPACITY_PATHS"))
	if err != nil || paths != 4 && paths != 8 || capacityQuota(cpu) == "" {
		t.Fatal("explicit robot CPU and 4/8 candidate profile required")
	}
	for _, healthy := range []int{0, paths/2 - 1, paths - 1} {
		t.Run(fmt.Sprint(healthy), func(t *testing.T) {
			applicationMixedCandidatesProfile(t, healthy, rebuild == "1", paths, cpu, layout)
		})
	}
}

type capacityGroup struct {
	file  *os.File
	path  string
	quota string
	model string
	cpus  string
	scope string
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

func newCapacityGroup(t *testing.T, cpu, cpus string) *capacityGroup {
	t.Helper()
	requireIsolatedGuest(t) // Check before the first filesystem mutation.
	quota := capacityQuota(cpu)
	if quota == "" || cpus != "" && cpus != "0" && cpus != "1" {
		t.Fatal("unsupported CPU profile")
	}
	const root = "/sys/fs/cgroup"
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil || !strings.Contains(" "+strings.TrimSpace(string(controllers))+" ", " cpu ") {
		t.Fatal("guest CPU controller unavailable", err)
	}
	control := "+cpu"
	if cpus != "" {
		control += " +cpuset"
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(control), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp(root, "vpnctl-capacity-")
	if err != nil {
		t.Fatal(err)
	}
	g := &capacityGroup{path: path, quota: quota, cpus: cpus, scope: "robot-supervisor-and-two-actuators"}
	t.Cleanup(func() {
		if g.file != nil {
			g.file.Close()
		}
		// A failed restoration must never kill this test worker before it can
		// publish the failure. The disposable VM owns any remaining group.
		self, err := os.ReadFile("/proc/self/cgroup")
		if err != nil || strings.TrimSpace(string(self)) == "0::/"+filepath.Base(path) {
			t.Error("refusing to kill current or unproven worker cgroup", err)
			return
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
	if cpus != "" {
		mems, err := os.ReadFile(filepath.Join(root, "cpuset.mems.effective"))
		if err != nil || strings.TrimSpace(string(mems)) == "" {
			t.Fatal("guest cpuset memory nodes unavailable", err)
		}
		for name, value := range map[string][]byte{"cpuset.mems": mems, "cpuset.cpus": []byte(cpus)} {
			if err := os.WriteFile(filepath.Join(path, name), value, 0600); err != nil {
				t.Fatal(err)
			}
		}
		actual, err := os.ReadFile(filepath.Join(path, "cpuset.cpus.effective"))
		if err != nil || strings.TrimSpace(string(actual)) != cpus {
			t.Fatal("guest CPU mask not granted", err)
		}
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
	evidence := map[string]any{"scope": g.scope, "cpu_max": g.quota,
		"cpu_model": g.model, "guest_vcpus": runtime.NumCPU(),
		"cpu_stat": read("cpu.stat"), "cpu_pressure": read("cpu.pressure"),
		"initial_preparation_limited":          g.scope == "controller-relays-and-measurement",
		"controller_relay_measurement_limited": g.scope == "controller-relays-and-measurement"}
	if g.cpus != "" {
		actual := read("cpuset.cpus.effective")
		if actual != g.cpus {
			t.Fatal("role CPU mask changed", actual)
		}
		evidence["cpuset_cpus_effective"] = actual
	}
	return evidence
}

// All threads move together via cgroup.procs; descendants inherit the service
// group except robot commands created directly in their own group by clone3.
func (g *capacityGroup) moveWorker(t *testing.T) {
	t.Helper()
	requireIsolatedGuest(t)
	current, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	original, ok := strings.CutPrefix(strings.TrimSpace(string(current)), "0::/")
	if !ok || strings.Contains(original, "\n") || strings.Contains(original, "..") {
		t.Fatal("cannot identify original guest worker cgroup")
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	// Registered after the group's cleanup, so restoration runs before kill.
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", original, "cgroup.procs"), pid, 0600); err != nil {
			t.Error("restore worker cgroup", err)
		}
	})
	if err := os.WriteFile(filepath.Join(g.path, "cgroup.procs"), pid, 0600); err != nil {
		t.Fatal("place measurement worker", err)
	}
	g.requireMembership(t, os.Getpid(), true)
}

func (g *capacityGroup) placement(t *testing.T, pid int) map[string]any {
	t.Helper()
	g.requireMembership(t, pid, true)
	threads, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "task"))
	if err != nil {
		t.Fatal("read role threads", err)
	}
	observed := 0
	for _, thread := range threads {
		status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", thread.Name(), "status"))
		if os.IsNotExist(err) { // A short-lived command thread may have exited.
			continue
		}
		if err != nil {
			t.Fatal("read role thread affinity", err)
		}
		allowed := ""
		for _, line := range strings.Split(string(status), "\n") {
			if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
				allowed = strings.TrimSpace(value)
			}
		}
		if allowed != g.cpus {
			t.Fatal("incorrect role thread affinity", pid, thread.Name(), allowed, g.cpus)
		}
		observed++
	}
	if observed == 0 {
		t.Fatal("no live role threads observed", pid)
	}
	return map[string]any{"cpus": g.cpus, "threads": observed}
}
