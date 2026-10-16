// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The attacker is a separate process so server CPU/RSS includes the API and
// sample producer only. No sockets other than this test's private Unix endpoint.
func TestAPILoadClientHelper(t *testing.T) {
	dir := os.Getenv("VPNCTL_UPLINK_LOAD_DIR")
	if dir == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for ctx.Err() == nil {
				c, err := Dial(ctx, dir, uint32(os.Geteuid()))
				if err != nil {
					continue
				}
				c.SetDeadline(time.Now().Add(300 * time.Millisecond))
				switch index {
				case 0, 1:
					fmt.Fprint(c, "GET /v1/events HTTP/1.1\r\nHost: uplink\r\n\r\n")
					select {
					case <-ctx.Done():
					case <-time.After(300 * time.Millisecond):
					}
				case 2, 3:
					fmt.Fprint(c, "GET /v1/status HTTP/1.1\r\nX-Slow:")
					select {
					case <-ctx.Done():
					case <-time.After(300 * time.Millisecond):
					}
				default:
					fmt.Fprint(c, "GET /v1/status HTTP/1.1\r\nHost: uplink\r\n\r\n")
					if r, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
						io.Copy(io.Discard, io.LimitReader(r.Body, MaxRecordBytes+1))
						r.Body.Close()
					}
				}
				c.Close()
			}
		}(i)
	}
	wg.Wait()
}

type apiResources struct {
	fd, goroutines, rssKB int
	cpu                   float64
}

func resources(t *testing.T) apiResources {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	pages, err := strconv.Atoi(strings.Fields(string(b))[1])
	if err != nil {
		t.Fatal(err)
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return apiResources{len(fds), runtime.NumGoroutine(), pages * os.Getpagesize() / 1024, float64(usage.Utime.Nano()+usage.Stime.Nano()) / 1e9}
}

func TestAPIFloodResourceAndProducerIsolation(t *testing.T) {
	s, source, dir := apiFixture(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				v := source.Snapshot()
				v.Revision++
				source.value.Store(&v)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	baseline := resources(t)
	time.Sleep(5 * time.Second)
	idle := resources(t)
	beforeRevision := source.Snapshot().Revision
	cmd := exec.Command(os.Args[0], "-test.run=^TestAPILoadClientHelper$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "VPNCTL_UPLINK_LOAD_DIR="+dir, "GOMAXPROCS=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	peak := idle
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for running := true; running; {
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal("load helper", err)
			}
			running = false
		case <-deadline.C:
			cmd.Process.Kill()
			<-finished
			t.Fatal("load client exceeded fixed bound")
		case <-tick.C:
			r := resources(t)
			peak.fd = max(peak.fd, r.fd)
			peak.goroutines = max(peak.goroutines, r.goroutines)
			peak.rssKB = max(peak.rssKB, r.rssKB)
		}
	}
	after := resources(t)
	if peak.fd-idle.fd > 48 || peak.goroutines-idle.goroutines > 48 || peak.rssKB-idle.rssKB > 64*1024 || after.cpu-idle.cpu > 1.0 {
		t.Fatal("API resource budget exceeded", peak.fd-idle.fd, peak.goroutines-idle.goroutines, peak.rssKB-idle.rssKB, after.cpu-idle.cpu)
	}
	if source.Snapshot().Revision-beforeRevision < 40 || s.Stats().Limited == 0 {
		t.Fatal("producer stalled or overload not exercised")
	}
	s.Close()
	if s.Stats().Connections != 0 || s.Stats().Streams != 0 {
		t.Fatal("shutdown leaked active handlers")
	}
	t.Logf("API_RESOURCE baseline_cpu=%.4f load_cpu=%.4f fd_delta=%d goroutine_delta=%d rss_kb_delta=%d denied=%d limited=%d", idle.cpu-baseline.cpu, after.cpu-idle.cpu, peak.fd-idle.fd, peak.goroutines-idle.goroutines, peak.rssKB-idle.rssKB, s.Stats().Denied, s.Stats().Limited)
}
