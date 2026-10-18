//go:build linux && vpnctl_profile

package selectorprofile

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"testing"
	"time"
)

func TestBoundedWriter(t *testing.T) {
	for _, size := range []int{0, 3, 4, 8} {
		var output bytes.Buffer
		w := newBoundedWriter(&output, 4)
		input := bytes.Repeat([]byte{'x'}, size)
		if n, err := w.Write(input); n != size || err != nil {
			t.Fatalf("profiler must drain: %d %v", n, err)
		}
		if output.Len() != min(size, 4) || w.truncated != (size > 4) {
			t.Fatalf("incorrect limit accounting: %+v", w)
		}
		w.Write([]byte("yyyy"))
		if output.Len() != 4 || w.truncated != (size > 0) {
			t.Fatal("second write escaped bound")
		}
	}
	for _, writer := range []io.Writer{failedWriter{}, shortWriter{}} {
		w := newBoundedWriter(writer, 4)
		w.Write([]byte("abc"))
		if w.err == nil {
			t.Fatal("write failure silently became a complete profile")
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) {
	return 0, errors.New("private path must not be reported")
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func readResult(t *testing.T, dir string) result {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		b, _ := os.ReadFile(filepath.Join(dir, "result.json"))
		var r result
		if json.Unmarshal(b, &r) == nil {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("bounded collector did not finish")
	return result{}
}

func TestCollectorWaitsForQualificationAndProducesBoundedProfiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app2")
	if err := start(dir, time.Second, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cpu.pprof")); !os.IsNotExist(err) {
		t.Fatal("CPU collection started before the qualification trigger")
	}
	if err := os.WriteFile(filepath.Join(dir, "start"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	r := readResult(t, dir)
	if r.Status != "complete" || r.PID != os.Getpid() || r.Role != "app2" || r.Clock != "CLOCK_MONOTONIC" || len(r.Profiles) != 3 {
		t.Fatalf("incomplete producer identity/profiles: %+v", r)
	}
	if r.CPUStartBefore < r.TriggerSeen || r.CPUStartAfter < r.CPUStartBefore || r.CPUStopBefore-r.CPUStartAfter < int64(50*time.Millisecond) || r.CPUStopAfter < r.CPUStopBefore {
		t.Fatal("invalid sampling boundaries", r)
	}
	for _, p := range r.Profiles {
		b, err := os.ReadFile(filepath.Join(dir, p.Name))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if p.Status != "complete" || p.Bytes != len(b) || p.Bytes > profileLimit || p.SHA256 != hex.EncodeToString(h[:]) || p.Finished < p.Started {
			t.Fatalf("invalid retained profile evidence: %+v", p)
		}
		gz, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, gz); err != nil {
			t.Fatal(err)
		}
		gz.Close()
		info, _ := os.Stat(filepath.Join(dir, p.Name))
		if info.Mode().Perm() != 0600 {
			t.Fatal("public profile")
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("public directory")
	}
}

func TestCollectorDoesNotOverwriteOrFollowExistingDirectory(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	os.Mkdir(existing, 0700)
	os.WriteFile(filepath.Join(existing, "cpu.pprof"), []byte("original"), 0600)
	link := filepath.Join(root, "link")
	os.Symlink(existing, link)
	for _, path := range []string{existing, link} {
		if start(path, time.Second, time.Millisecond) == nil {
			t.Fatal("reused untrusted directory")
		}
	}
	got, _ := os.ReadFile(filepath.Join(existing, "cpu.pprof"))
	if string(got) != "original" {
		t.Fatal("overwrote evidence")
	}
}

func TestCollectorTimeoutAndUnsafeTriggerAreUnavailable(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "app2")
		wait := 30 * time.Millisecond
		if unsafe {
			wait = time.Second
		}
		if err := start(dir, wait, time.Millisecond); err != nil {
			t.Fatal(err)
		}
		want := "trigger_timeout"
		if unsafe {
			os.Symlink("ready.json", filepath.Join(dir, "start"))
			want = "invalid_trigger"
		}
		r := readResult(t, dir)
		if r.Status != want || len(r.Profiles) != 0 {
			t.Fatalf("unsafe/missing trigger treated as success: %+v", r)
		}
	}
}

func TestCollectorDoesNotStopAnotherCPUProfiler(t *testing.T) {
	var other bytes.Buffer
	if err := pprof.StartCPUProfile(&other); err != nil {
		t.Fatal(err)
	}
	defer pprof.StopCPUProfile()
	dir := filepath.Join(t.TempDir(), "app2")
	if err := start(dir, time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "start"), nil, 0600)
	if r := readResult(t, dir); r.Status != "cpu_busy" {
		t.Fatal("ownership conflict lost", r)
	}
	if err := pprof.StartCPUProfile(io.Discard); err == nil {
		pprof.StopCPUProfile()
		t.Fatal("collector stopped the existing owner's CPU profiler")
	}
}
