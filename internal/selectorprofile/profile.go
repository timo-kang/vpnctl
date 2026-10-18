//go:build linux && vpnctl_profile

// Package selectorprofile is an experiment-only profiler. Normal builds contain
// neither this package nor its CLI hook. It never controls the selector's life.
package selectorprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"

	"golang.org/x/sys/unix"
)

const profileLimit = 256 << 10

type profile struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	Started  int64  `json:"started_monotonic_ns"`
	Finished int64  `json:"finished_monotonic_ns"`
}

type result struct {
	SchemaVersion  int       `json:"schema_version"`
	Status         string    `json:"status"`
	Role           string    `json:"role"`
	PID            int       `json:"pid"`
	Runtime        string    `json:"runtime"`
	Revision       string    `json:"revision"`
	Dirty          string    `json:"vcs_modified"`
	Clock          string    `json:"clock"`
	Duration       int64     `json:"requested_duration_ns"`
	MemSampleRate  int       `json:"mem_profile_rate"`
	TriggerSeen    int64     `json:"trigger_seen_monotonic_ns"`
	CPUStartBefore int64     `json:"cpu_start_before_monotonic_ns"`
	CPUStartAfter  int64     `json:"cpu_start_after_monotonic_ns"`
	CPUStopBefore  int64     `json:"cpu_stop_before_monotonic_ns"`
	CPUStopAfter   int64     `json:"cpu_stop_after_monotonic_ns"`
	Profiles       []profile `json:"profiles"`
}

// Start arms a single eight-second sample. A zero-byte private "start" file
// from the fixture triggers it after both application baselines exist. Failure
// to trigger within two minutes is diagnostic unavailability, not an app exit.
func Start(directory string) error {
	return start(directory, 2*time.Minute, 8*time.Second)
}

func start(directory string, wait, duration time.Duration) error {
	if err := os.Mkdir(directory, 0700); err != nil {
		return errors.New("profile_directory_unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return errors.New("profile_directory_unavailable")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return errors.New("profile_directory_unavailable")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm() != 0700 {
		root.Close()
		return errors.New("profile_directory_changed")
	}
	r := result{SchemaVersion: 1, Status: "waiting", Role: "app2", PID: os.Getpid(),
		Runtime: runtime.Version(), Revision: "unknown", Dirty: "unknown",
		Clock: "CLOCK_MONOTONIC", Duration: int64(duration), MemSampleRate: runtime.MemProfileRate}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				r.Revision = setting.Value
			case "vcs.modified":
				r.Dirty = setting.Value
			}
		}
	}
	if err := writeResult(root, "ready.json", r); err != nil {
		root.Close()
		return errors.New("profile_metadata_unavailable")
	}
	go func() {
		defer root.Close()
		r.Status = awaitTrigger(root, wait)
		if r.Status == "triggered" {
			collect(root, &r, duration)
		}
		// A missing final file (including process termination before flush) is
		// unavailable. Never extend the worker's deadline or change its exit.
		_ = writeResult(root, "result.json", r)
	}()
	return nil
}

func awaitTrigger(root *os.Root, wait time.Duration) string {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := root.Lstat("start")
		if err == nil {
			if !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0600 {
				return "invalid_trigger"
			}
			return "triggered"
		}
		if !os.IsNotExist(err) {
			return "trigger_unavailable"
		}
		select {
		case <-timer.C:
			return "trigger_timeout"
		case <-ticker.C:
		}
	}
}

func monotonic() int64 {
	var stamp unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp) != nil {
		return 0
	}
	return stamp.Nano()
}

func collect(root *os.Root, r *result, duration time.Duration) {
	r.TriggerSeen = monotonic()
	if r.TriggerSeen == 0 {
		r.Status = "clock_unavailable"
		return
	}
	r.Profiles = append(r.Profiles, allocationProfile(root, "allocs-before.pprof"))
	f, err := root.OpenFile("cpu.pprof", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		r.Status = "cpu_file_unavailable"
		return
	}
	w := newBoundedWriter(f, profileLimit)
	r.CPUStartBefore = monotonic()
	if r.CPUStartBefore == 0 {
		f.Close()
		r.Status = "clock_unavailable"
		return
	}
	if pprof.StartCPUProfile(w) != nil {
		f.Close()
		r.Status = "cpu_busy"
		return // Do not stop the profiler belonging to another caller.
	}
	r.CPUStartAfter = monotonic()
	time.Sleep(duration)
	r.CPUStopBefore = monotonic()
	pprof.StopCPUProfile() // Joins the writer before its state is inspected.
	r.CPUStopAfter = monotonic()
	w.close(f)
	p := w.evidence("cpu.pprof", r.CPUStartBefore, r.CPUStopAfter)
	r.Profiles = append(r.Profiles, p, allocationProfile(root, "allocs-after.pprof"))
	r.Status = "complete"
	for _, p := range r.Profiles {
		if p.Status != "complete" {
			r.Status = "profile_unavailable"
		}
	}
	if r.CPUStartAfter < r.CPUStartBefore || r.CPUStopBefore < r.CPUStartAfter || r.CPUStopAfter < r.CPUStopBefore {
		r.Status = "clock_unavailable"
	}
}

func allocationProfile(root *os.Root, name string) profile {
	started := monotonic()
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return profile{Name: name, Status: "file_unavailable"}
	}
	w := newBoundedWriter(f, profileLimit)
	// Default sampling, no runtime.GC or runtime tuning. This cumulative
	// profile can lag by two GC cycles and includes profiler allocations.
	if err := pprof.Lookup("allocs").WriteTo(w, 0); err != nil {
		w.err = err
	}
	w.close(f)
	return w.evidence(name, started, monotonic())
}

// Drain the profiler even after a cap or disk error; report partial output
// explicitly. This bounds disk use without interfering with the runtime writer.
type boundedWriter struct {
	destination  io.Writer
	limit, bytes int
	truncated    bool
	err          error
	hash         hash.Hash
}

func newBoundedWriter(w io.Writer, limit int) *boundedWriter {
	return &boundedWriter{destination: w, limit: limit, hash: sha256.New()}
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	want := min(len(p), w.limit-w.bytes)
	if want < len(p) {
		w.truncated = true
	}
	if want > 0 && w.err == nil {
		n, err := w.destination.Write(p[:want])
		w.bytes += n
		w.hash.Write(p[:n])
		if err == nil && n != want {
			err = io.ErrShortWrite
		}
		w.err = err
	}
	return len(p), nil
}

func (w *boundedWriter) close(f *os.File) {
	if err := f.Close(); err != nil && w.err == nil {
		w.err = err
	}
}

func (w *boundedWriter) evidence(name string, start, end int64) profile {
	p := profile{Name: name, Status: "complete", Bytes: w.bytes,
		SHA256: hex.EncodeToString(w.hash.Sum(nil)), Started: start, Finished: end}
	switch {
	case w.err != nil:
		p.Status = "write_error"
	case w.truncated:
		p.Status = "truncated"
	case start == 0 || end < start:
		p.Status = "clock_unavailable"
	}
	return p
}

func writeResult(root *os.Root, name string, r result) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(r)
	return errors.Join(err, f.Close())
}
