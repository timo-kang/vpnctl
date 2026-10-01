//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/relaycache"
)

func holdM3KernelLock() error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: "@vpnctl.relay-apply.v1"}); err != nil {
		return err
	}
	if err = os.WriteFile(os.Getenv("VPNCTL_LOCK_READY"), []byte("locked"), 0600); err != nil {
		return err
	}
	select {}
}

func TestNetns_M3LeasePressure(t *testing.T) {
	requireNetwork(t)
	for _, fault := range []string{"cache-lock", "namespace-lock", "slow-kernel", "stdout-backpressure"} {
		t.Run(fault, func(t *testing.T) {
			f := newM3AuthorityFixture(t)
			report := map[string]any{"schema_version": 1, "fault": fault, "completed": false}
			defer func() { writeM3Report(t, filepath.Join(f.results, "pressure.json"), report) }()
			streams := []*networkProcess{}
			for _, p := range f.plan.Paths {
				if !f.probe(p).OK {
					t.Fatal("baseline unreachable", p.PathID)
				}
				s := startNetworkProcess(t, f.robot, filepath.Join(f.results, p.PathID+"-pressure-stream.jsonl"), []string{"VPNCTL_WORKER=lease-stream", "VPNCTL_PROBE_SOURCE=" + strings.TrimSuffix(p.InnerAddress, "/32")}, f.worker, "-test.run=^TestNetworkWorker$")
				streams = append(streams, s)
				eventually(t, 3*time.Second, "established stream", func() error {
					b, _ := os.ReadFile(s.log)
					if !strings.Contains(string(b), `"ok":true`) {
						return fmt.Errorf("no echo")
					}
					return nil
				})
			}
			var release []func()
			evidence := map[string]any{}
			report["fault_evidence"] = evidence
			for _, r := range f.recipients {
				r.watch.terminate(t)
				switch fault {
				case "cache-lock":
					c, err := relaycache.OpenDeployment(r.cache, relaycache.DeploymentOptions{PrincipalID: "agent", RelayID: r.relay})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.Close() })
					release = append(release, func() { c.Close() })
					r.start()
				case "namespace-lock":
					ready := filepath.Join(f.private, r.relay+".locked")
					p := startNetworkProcess(t, r.ns, filepath.Join(f.results, r.relay+"-lock.log"), []string{"VPNCTL_WORKER=lease-lock", "VPNCTL_LOCK_READY=" + ready}, f.worker, "-test.run=^TestNetworkWorker$")
					eventually(t, 3*time.Second, "namespace lock holder", func() error { _, err := os.Stat(ready); return err })
					release = append(release, p.stop)
					r.start()
				case "slow-kernel":
					dir := filepath.Join(f.private, r.relay+"-slow")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					// Private generated path contains no shell metacharacters.
					script := "#!/bin/sh\nprintf invoked >> '" + filepath.Join(dir, "invoked") + "'\nsleep 30\nexec /usr/sbin/nft \"$@\"\n"
					if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
						t.Fatal(err)
					}
					r.start("PATH=" + dir + ":" + os.Getenv("PATH"))
					eventually(t, 5*time.Second, "slow kernel invocation", func() error { _, err := os.Stat(filepath.Join(dir, "invoked")); return err })
				case "stdout-backpressure":
					reader, writer, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { reader.Close(); writer.Close() })
					capacity, err := unix.FcntlInt(writer.Fd(), unix.F_SETPIPE_SZ, 4096)
					if err != nil {
						t.Fatal(err)
					}
					if n, err := writer.Write(make([]byte, capacity)); err != nil || n != capacity {
						t.Fatal("pipe not full", n, err)
					}
					cmd := netCommand(context.Background(), r.ns, append(r.args("supervise", ""), "--refresh-interval", "1s")...)
					cmd.Stdout = writer
					if err = cmd.Start(); err != nil {
						t.Fatal(err)
					}
					p := &networkProcess{cmd: cmd}
					t.Cleanup(p.stop)
					r.watch = p
					release = append(release, func() { p.stop(); reader.Close(); writer.Close() })
					report["pipe_capacity_bytes"] = capacity
					evidence[r.relay] = map[string]any{"filled_pipe_bytes": capacity}
				}
			}
			at := time.Now().UTC()
			report["fault_injected_at"] = at
			// A first cycle can arm before blocking on stdout. Two seconds of
			// setup allowance plus the 10s lease; no CLI inspection until after.
			time.Sleep(12 * time.Second)
			for _, r := range f.recipients {
				if fault == "stdout-backpressure" {
					continue
				}
				b, err := os.ReadFile(r.watch.log)
				if err != nil {
					t.Fatal(err)
				}
				var cycles int
				var maxMS int64
				for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
					var v m3SupervisorReport
					if err = json.Unmarshal([]byte(line), &v); err != nil {
						t.Fatal(err)
					}
					cycles++
					if v.CycleMS > maxMS {
						maxMS = v.CycleMS
					}
					if v.State != "degraded" {
						t.Fatal("injection did not degrade supervisor", fault, v)
					}
				}
				if cycles == 0 || maxMS > 5500 {
					t.Fatal("invalid cycle budget evidence", cycles, maxMS)
				}
				evidence[r.relay] = map[string]any{"cycles": cycles, "max_cycle_ms": maxMS}
			}
			report["kernel_after_deadline"] = f.snapshot()
			blocked := map[string]m3Probe{}
			for _, p := range f.plan.Paths {
				v := f.probe(p)
				blocked[p.PathID] = v
				if v.OK {
					t.Fatal("overload kept traffic open", p.PathID)
				}
			}
			report["blocked_probes"] = blocked
			for _, s := range streams {
				s.stop()
				b, err := os.ReadFile(s.log)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(b), `"ok":false`) {
					t.Fatal("existing TCP not interrupted")
				}
			}
			for _, r := range f.recipients {
				if got := netOutput(t, r.ns, "wg", "show", "interfaces"); len(strings.Fields(got)) != 2 {
					t.Fatal("pressure test must retain managed links", got)
				}
				if fault == "stdout-backpressure" {
					// The completed cycle is blocked on its filled output pipe;
					// graceful shutdown cannot drain a sink deliberately not read.
					r.watch.stop()
				} else {
					// Preserve the completed approval state while removing the
					// pressure. Interrupted refresh is exercised separately.
					r.watch.terminate(t)
				}
				(relayUplink{relay: r.ns}).nft(t, `table inet pressure_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.11 tcp dport 9443 counter drop
 }
}`)
			}
			for _, fn := range release {
				fn()
			}
			for _, r := range f.recipients {
				r.start()
			}
			time.Sleep(3 * time.Second)
			for _, p := range f.plan.Paths {
				if f.probe(p).OK {
					t.Fatal("cached approval revived expired lease")
				}
			}
			for _, r := range f.recipients {
				rules := netOutput(t, r.ns, "nft", "list", "table", "inet", "pressure_outage")
				if strings.Contains(rules, "counter packets 0 bytes 0") {
					t.Fatal("HTTP failure injection not exercised")
				}
				netOutput(t, r.ns, "nft", "delete", "table", "inet", "pressure_outage")
				r.ready()
			}
			for _, p := range f.plan.Paths {
				if !f.probe(p).OK {
					t.Fatal("fresh approval did not recover", p.PathID)
				}
			}
			report["cached_rearm_rejected"] = true
			report["fresh_approval_recovered"] = true
			report["completed"] = true
		})
	}
}
