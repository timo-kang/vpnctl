//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runtimeStatFixture(start string) string {
	fields := make([]string, 40)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[11], fields[12], fields[19], fields[39] = "S", "13", "17", start, "23"
	return "42 (name with ) and space) " + strings.Join(fields, " ")
}
func TestRuntimeCounterParsers(t *testing.T) {
	state, start, user, system, blkio, err := parseRuntimeStat(runtimeStatFixture("19"))
	if err != nil || state != "S" || start != 19 || user != 13 || system != 17 || blkio != 23 {
		t.Fatalf("misread proc stat: %s %d %d %d %d %v", state, start, user, system, blkio, err)
	}
	for _, bad := range []string{"", "42 (name) S 1", runtimeStatFixture("-1"), runtimeStatFixture("overflow")} {
		if _, _, _, _, _, err := parseRuntimeStat(bad); err == nil {
			t.Fatalf("accepted malformed stat %q", bad)
		}
	}
	if got, err := parseRuntimeSched("31 37 41\n"); err != nil || got != [3]uint64{31, 37, 41} {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", "1 2", "1 2 3 4", "1 -2 3", "18446744073709551616 2 3"} {
		if _, err := parseRuntimeSched(bad); err == nil {
			t.Fatalf("accepted malformed schedstat %q", bad)
		}
	}
}
func runtimeProcFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, raw := range map[string]string{"42/stat": runtimeStatFixture("19"), "42/task/42/stat": runtimeStatFixture("19"), "42/task/42/schedstat": "31 37 41", "42/task/42/wchan": "io_schedule", "42/io": "read_bytes: 4096\n"} {
		target := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestRuntimeRoleIdentityAndMissingness(t *testing.T) {
	root := runtimeProcFixture(t)
	role := runtimeRole{PID: 42, Start: 19}
	row := readRuntimeRole(root, role)
	if row.Error != "" || row.Missing != 0 || len(row.Threads) != 1 || row.Begin > row.End || row.Threads[0].Values != [8]uint64{42, 19, 13, 17, 31, 37, 23, 41} || row.Threads[0].Wchan != "io_schedule" {
		t.Fatalf("invalid snapshot %+v", row)
	}
	role.Start = 20
	if row := readRuntimeRole(root, role); row.Error != "process_identity_changed" || len(row.Threads) != 0 {
		t.Fatalf("reused PID accepted %+v", row)
	}
	role.Start = 19
	if err := os.Remove(filepath.Join(root, "42/task/42/schedstat")); err != nil {
		t.Fatal(err)
	}
	row = readRuntimeRole(root, role)
	if row.Missing != 1 || len(row.Threads) != 0 {
		t.Fatalf("missing thread became zero counters %+v", row)
	}
	if err := os.Remove(filepath.Join(root, "42/io")); err != nil {
		t.Fatal(err)
	}
	if row := readRuntimeRole(root, role); row.Error != "io_unavailable" || row.IO != "" {
		t.Fatalf("missing IO hidden %+v", row)
	}
	for i := 0; i < 128; i++ {
		if err := os.Mkdir(filepath.Join(root, "42/task", fmt.Sprint(1000+i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if row := readRuntimeRole(root, role); row.Error != "thread_inventory_unavailable_or_limit" {
		t.Fatalf("unbounded thread scan %+v", row)
	}
}
func TestRuntimeCaptureOffAndEndReserve(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "counter")
	if err != nil {
		t.Fatal(err)
	}
	c := &runtimeCapture{file: file, stop: make(chan struct{}), done: make(chan struct{}), roles: map[string]runtimeRole{"unavailable": {PID: -1}}, begin: managerMono(), ticks: 100}
	go c.loop()
	// OFF never samples even when a full sampling period elapses.
	time.Sleep(1100 * time.Millisecond)
	report := map[string]any{}
	c.finish(report)
	if c.samples != 0 {
		t.Fatal("OFF sampled", c.samples)
	}
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	var end map[string]any
	if err := json.Unmarshal(raw, &end); err != nil || end["kind"] != "original_end" {
		t.Fatal(string(raw), err)
	}
	if report["runtime_counters"].(map[string]any)["error"] != "" {
		t.Fatal(report)
	}
	file, err = os.CreateTemp(t.TempDir(), "limit")
	if err != nil {
		t.Fatal(err)
	}
	c = &runtimeCapture{file: file, stop: make(chan struct{}), done: make(chan struct{}), bytes: runtimeCounterLimit - runtimeEndReserve, begin: managerMono()}
	if c.emit(map[string]any{"kind": "sample"}) == nil {
		t.Fatal("sample exceeded reserved space")
	}
	close(c.done)
	c.finish(report)
	if report["runtime_counters"].(map[string]any)["error"] != "" {
		t.Fatal("reserved end lost", report)
	}
	var disabled *runtimeCapture
	disabled.add("unused", 0)
	disabled.finish(report)
}
