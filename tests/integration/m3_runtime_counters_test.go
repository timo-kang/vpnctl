//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Test-only, opt-in sampling. It never changes a product deadline or verdict.
// Thread counters omit exited tasks' unsampled tails and short-lived commands;
// group counters include those commands but do not identify their blocked stacks.
const runtimeCounterLimit = 4 << 20
const runtimeCounterSamples = 361
const runtimeEndReserve = 2048

type runtimeRole struct {
	PID   int    `json:"pid"`
	Start uint64 `json:"start_ticks"`
}
type runtimeThread struct {
	Values [8]uint64 `json:"counters"` // tid,start,user_ticks,system_ticks,cpu_ns,runqueue_ns,blkio_ticks,slices
	State  string    `json:"state"`
	Wchan  string    `json:"wchan"`
}
type runtimeRoleSample struct {
	Identity runtimeRole     `json:"identity"`
	Begin    int64           `json:"begin_monotonic_ns"`
	End      int64           `json:"end_monotonic_ns"`
	Threads  []runtimeThread `json:"threads"`
	Missing  int             `json:"missing_threads"`
	IO       string          `json:"io"`
	Error    string          `json:"error,omitempty"`
}
type runtimeCapture struct {
	enabled        bool
	file           *os.File
	stop, done     chan struct{}
	mu             sync.Mutex
	roles          map[string]runtimeRole
	groups         map[string]string
	begin          int64
	samples, bytes int
	problem        string
	ticks          int
	samplerCPU     int64
}

func parseRuntimeStat(raw string) (state string, start, user, system, blkio uint64, err error) {
	end := strings.LastIndex(raw, ") ")
	if end < 0 {
		err = fmt.Errorf("stat comm delimiter")
		return
	}
	fields := strings.Fields(raw[end+2:]) // starts at field 3
	if len(fields) < 40 || len(fields[0]) != 1 {
		err = fmt.Errorf("short stat")
		return
	}
	state = fields[0]
	values := []*uint64{&start, &user, &system, &blkio}
	for i, index := range []int{19, 11, 12, 39} {
		*values[i], err = strconv.ParseUint(fields[index], 10, 64)
		if err != nil {
			return
		}
	}
	return
}

func parseRuntimeSched(raw string) ([3]uint64, error) {
	var result [3]uint64
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return result, fmt.Errorf("schedstat field count")
	}
	for i, s := range fields {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return result, err
		}
		result[i] = n
	}
	return result, nil
}

func readRuntimeRole(proc string, role runtimeRole) runtimeRoleSample {
	out := runtimeRoleSample{Identity: role, Begin: managerMono()}
	base := filepath.Join(proc, strconv.Itoa(role.PID))
	raw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		out.Error = "process_unavailable"
		out.End = managerMono()
		return out
	}
	_, start, _, _, _, err := parseRuntimeStat(string(raw))
	if err != nil || start != role.Start {
		out.Error = "process_identity_changed"
		out.End = managerMono()
		return out
	}
	entries, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil || len(entries) > 128 {
		out.Error = "thread_inventory_unavailable_or_limit"
		out.End = managerMono()
		return out
	}
	for _, entry := range entries {
		tid, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			out.Missing++
			continue
		}
		path := filepath.Join(base, "task", entry.Name())
		raw, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			out.Missing++
			continue
		}
		state, birth, user, system, blkio, err := parseRuntimeStat(string(raw))
		if err != nil {
			out.Missing++
			continue
		}
		raw, err = os.ReadFile(filepath.Join(path, "schedstat"))
		if err != nil {
			out.Missing++
			continue
		}
		sched, err := parseRuntimeSched(string(raw))
		if err != nil {
			out.Missing++
			continue
		}
		wchan, err := os.ReadFile(filepath.Join(path, "wchan"))
		if err != nil {
			out.Missing++
			continue
		}
		raw, err = os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			out.Missing++
			continue
		}
		_, after, _, _, _, err := parseRuntimeStat(string(raw))
		if err != nil || after != birth {
			out.Missing++
			continue
		}
		out.Threads = append(out.Threads, runtimeThread{Values: [8]uint64{tid, birth, user, system, sched[0], sched[1], blkio, sched[2]}, State: state, Wchan: strings.TrimSpace(string(wchan))})
	}
	if raw, err = os.ReadFile(filepath.Join(base, "io")); err == nil {
		out.IO = string(raw)
	} else {
		out.Error = "io_unavailable"
	}
	raw, err = os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		out.Error = "process_exited_during_read"
	} else {
		_, after, _, _, _, err := parseRuntimeStat(string(raw))
		if err != nil || after != role.Start {
			out.Error = "process_identity_changed"
			out.Threads = nil
			out.IO = ""
		}
	}
	out.End = managerMono()
	return out
}

func startRuntimeCapture(t *testing.T, destination string, groups map[string]string, report map[string]any) *runtimeCapture {
	t.Helper()
	mode := os.Getenv("VPNCTL_VM_RUNTIME_COUNTERS")
	if mode == "" {
		return nil
	}
	if mode != "0" && mode != "1" {
		t.Fatal("invalid runtime counter mode")
	}
	requireIsolatedGuest(t)
	for _, path := range []string{"/proc/sys/kernel/sched_schedstats", "/proc/sys/kernel/task_delayacct"} {
		b, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(b)) != "1" {
			t.Fatal("guest accounting must be enabled before all fixture tasks")
		}
	}
	raw, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || ticks <= 0 {
		t.Fatal("invalid clock tick rate")
	}
	file, err := os.OpenFile(filepath.Join(destination, "runtime-counters.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	c := &runtimeCapture{enabled: mode == "1", file: file, stop: make(chan struct{}), done: make(chan struct{}), roles: map[string]runtimeRole{}, groups: groups, begin: managerMono(), ticks: ticks}
	if err := c.emit(map[string]any{"kind": "header", "schema_version": 1, "enabled": c.enabled, "clock_ticks_per_second": ticks, "interval_ns": int64(time.Second), "begin_monotonic_ns": c.begin, "begin_wall": time.Now().UTC(), "thread_fields": []string{"tid", "start_ticks", "user_ticks", "system_ticks", "cpu_ns", "runqueue_ns", "blkio_ticks", "slices"}}); err != nil {
		file.Close()
		t.Fatal(err)
	}
	report["runtime_counters"] = map[string]any{"enabled": c.enabled, "schema_version": 1}
	go c.loop()
	return c
}

func (c *runtimeCapture) add(name string, pid int) {
	if c == nil {
		return
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	var start uint64
	if err == nil {
		_, start, _, _, _, err = parseRuntimeStat(string(raw))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.problem = "role_registration_unavailable"
		return
	}
	c.roles[name] = runtimeRole{PID: pid, Start: start}
}

func (c *runtimeCapture) emit(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return c.writeLine(raw, runtimeCounterLimit-runtimeEndReserve)
}

func (c *runtimeCapture) writeLine(raw []byte, limit int) error {
	if c.bytes+len(raw) > limit {
		return fmt.Errorf("counter_byte_limit")
	}
	n, err := c.file.Write(raw)
	c.bytes += n
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}

func (c *runtimeCapture) loop() {
	defer close(c.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var beginCPU unix.Timespec
	cpuErr := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &beginCPU)
	defer func() {
		var endCPU unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &endCPU); err == nil && cpuErr == nil {
			c.samplerCPU = endCPU.Nano() - beginCPU.Nano()
		} else {
			c.samplerCPU = -1
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
			if !c.enabled {
				continue
			}
			select {
			case <-c.stop:
				return
			default:
			}
			if c.samples >= runtimeCounterSamples {
				c.mu.Lock()
				c.problem = "sample_limit"
				c.mu.Unlock()
				return
			}
			var before, after unix.Timespec
			err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &before)
			begin := managerMono()
			c.mu.Lock()
			roles := map[string]runtimeRole{}
			for k, v := range c.roles {
				roles[k] = v
			}
			c.mu.Unlock()
			sampled := map[string]runtimeRoleSample{}
			names := make([]string, 0, len(roles))
			for name := range roles {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				sampled[name] = readRuntimeRole("/proc", roles[name])
			}
			groups := map[string]map[string]string{}
			for name, path := range c.groups {
				values := map[string]string{}
				for _, field := range []string{"cpu.stat", "cpu.pressure", "io.stat", "io.pressure"} {
					raw, e := os.ReadFile(filepath.Join(path, field))
					if e != nil {
						values[field] = "unavailable"
					} else {
						values[field] = string(raw)
					}
				}
				groups[name] = values
			}
			cpuErr := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &after)
			value := map[string]any{"kind": "sample", "index": c.samples, "begin_monotonic_ns": begin, "end_monotonic_ns": managerMono(), "wall": time.Now().UTC(), "roles": sampled, "groups": groups}
			if err == nil && cpuErr == nil {
				value["read_cpu_ns"] = after.Nano() - before.Nano()
			} else {
				value["sampler_cpu_unavailable"] = true
			}
			if err := c.emit(value); err != nil {
				c.mu.Lock()
				c.problem = "write_or_byte_limit"
				c.mu.Unlock()
				return
			}
			c.samples++
		}
	}
}

func (c *runtimeCapture) finish(report map[string]any) {
	if c == nil {
		return
	}
	// Executed on all returns, including Fatal before publication qualification.
	// Publication's later registered defer freezes first; cleanup runs afterwards.
	end := managerMono()
	wall := time.Now().UTC()
	close(c.stop)
	<-c.done
	c.mu.Lock()
	problem := c.problem
	c.mu.Unlock()
	metadata := map[string]any{"schema_version": 1, "enabled": c.enabled, "original_end_monotonic_ns": end, "original_end_wall": wall, "begin_monotonic_ns": c.begin, "samples": c.samples, "bytes_before_end": c.bytes, "clock_ticks_per_second": c.ticks, "error": problem, "sampler_thread_cpu_ns": c.samplerCPU}
	raw, err := json.Marshal(map[string]any{"kind": "original_end", "metadata": metadata})
	if err == nil {
		err = c.writeLine(append(raw, '\n'), runtimeCounterLimit)
	}
	if err != nil {
		metadata["error"] = "end_write_failed"
	}
	if err := c.file.Close(); err != nil {
		metadata["error"] = "close_failed"
	}
	report["runtime_counters"] = metadata
}
