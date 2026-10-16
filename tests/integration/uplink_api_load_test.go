//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/uplinkapi"
)

// Runs only inside the robot netns in the owned VM. Load clients are placed in
// the existing measurement/server role, not the robot actuator CPU quota.
func TestVMUplinkAPILoadWorker(t *testing.T) {
	dirs := strings.Split(os.Getenv("VPNCTL_API_LOAD_DIRS"), ",")
	if len(dirs) != 2 {
		t.Skip("dedicated VM API client worker")
	}
	requireIsolatedGuestNamespace(t, true)
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
	defer cancel()
	type counters struct{ responses, limited, fresh atomic.Int64 }
	var counts [2]counters
	var wg sync.WaitGroup
	for app, dir := range dirs {
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func(app, worker int, dir string) {
				defer wg.Done()
				for ctx.Err() == nil {
					c, err := uplinkapi.Dial(ctx, dir, 0)
					if err != nil {
						select {
						case <-ctx.Done():
						case <-time.After(25 * time.Millisecond):
						}
						continue
					}
					c.SetDeadline(time.Now().Add(500 * time.Millisecond))
					if worker < 2 {
						if worker == 0 {
							fmt.Fprint(c, "GET /v1/events HTTP/1.1\r\nHost: uplink\r\n\r\n")
						} else {
							fmt.Fprint(c, "GET /v1/status HTTP/1.1\r\nX-Slow:")
						}
						select {
						case <-ctx.Done():
						case <-time.After(500 * time.Millisecond):
						}
						c.Close()
						continue
					}
					fmt.Fprint(c, "GET /v1/status HTTP/1.1\r\nHost: uplink\r\n\r\n")
					r, err := http.ReadResponse(bufio.NewReader(c), nil)
					if err == nil {
						if r.StatusCode == 429 {
							counts[app].limited.Add(1)
						}
						if r.StatusCode == 200 {
							var frame uplinkapi.Frame
							if json.NewDecoder(io.LimitReader(r.Body, uplinkapi.MaxRecordBytes+1)).Decode(&frame) == nil && frame.SchemaVersion == 1 {
								counts[app].responses.Add(1)
								clock, boot, err := relayapply.LocalUplinkClock()
								s := frame.Snapshot
								if err == nil && s.ClockDomain == clock && s.Availability == "reachable" && s.Freshness == "fresh" && boot >= s.ObservedBootNS && boot < s.ValidUntilBootNS {
									counts[app].fresh.Add(1)
								}
							}
						}
					}
					c.Close()
				}
			}(app, worker, dir)
		}
	}
	started := managerMono()
	if err := os.WriteFile(os.Getenv("VPNCTL_API_LOAD_REPORT")+".ready", []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	report := map[string]any{"enabled": true, "client_scope": "server-measurement",
		"started_monotonic_ns": started, "stopped_monotonic_ns": managerMono(),
		"parent_stopped": parent.Err() != nil && ctx.Err() == context.Canceled}
	for i, name := range []string{"app", "app2"} {
		report[name] = map[string]int64{"responses": counts[i].responses.Load(), "limited": counts[i].limited.Load(), "fresh_reachable": counts[i].fresh.Load()}
	}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("VPNCTL_API_LOAD_REPORT"), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func apiRuntime(t *testing.T, f *m3AuthorityFixture, target string) string {
	t.Helper()
	dir := filepath.Join(f.results, "api-"+target)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func startUplinkAPILoad(t *testing.T, f *m3AuthorityFixture, dirs []string, group, serverGroup *capacityGroup, report map[string]any) func() {
	t.Helper()
	file := filepath.Join(f.results, "api-load.json")
	var serverFD *os.File
	if serverGroup != nil {
		serverFD = serverGroup.file
	}
	load := startNetworkProcessInGroup(t, serverFD, f.robot, filepath.Join(f.results, "api-load.log"), []string{"VPNCTL_API_LOAD_DIRS=" + strings.Join(dirs, ","), "VPNCTL_API_LOAD_REPORT=" + file, "GOMAXPROCS=1"}, os.Args[0], "-test.run=^TestVMUplinkAPILoadWorker$", "-test.timeout=5m")
	if group != nil {
		group.requireMembership(t, load.cmd.Process.Pid, false)
	}
	if serverGroup != nil {
		serverGroup.requireMembership(t, load.cmd.Process.Pid, true)
	}
	eventually(t, 5*time.Second, "API load ready", func() error {
		_, err := os.Stat(file + ".ready")
		return err
	})
	windowStart := managerMono()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			windowEnd := managerMono()
			load.terminate(t)
			b, err := os.ReadFile(file)
			var counters map[string]any
			if err != nil || json.Unmarshal(b, &counters) != nil {
				if !t.Failed() {
					t.Error("API load report missing")
				}
				return
			}
			report["uplink_api_load"] = counters
			counters["window_started_monotonic_ns"] = windowStart
			counters["window_ended_monotonic_ns"] = windowEnd
			if t.Failed() {
				return
			}
			start, startOK := counters["started_monotonic_ns"].(float64)
			end, endOK := counters["stopped_monotonic_ns"].(float64)
			if !startOK || !endOK || start <= 0 || start > float64(windowStart) || end < float64(windowEnd) || counters["parent_stopped"] != true {
				t.Error("API load did not cover qualification window")
			}
			for _, name := range []string{"app", "app2"} {
				c, ok := counters[name].(map[string]any)
				if !ok {
					t.Error("API client evidence missing", name)
					continue
				}
				for key, minimum := range map[string]float64{"responses": 10, "limited": 1, "fresh_reachable": 1} {
					n, ok := c[key].(float64)
					if !ok || n < minimum {
						t.Error("API load did not exercise required response", name, key)
					}
				}
			}
		})
	}
	t.Cleanup(finish)
	return finish
}
