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
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayguard"
)

func TestNetns_M3NodeLease(t *testing.T) {
	requireNetwork(t)
	for _, placement := range []string{"colocated", "separate"} {
		for _, size := range []int{1, 4, 8} {
			t.Run(fmt.Sprintf("%s/%d", placement, size), func(t *testing.T) {
				underlays := 2
				if size == 8 {
					underlays = 4
				}
				f := newM3AuthorityFixtureWithOptions(t, m3AuthorityOptions{separateController: placement == "separate", independentRecipients: true, underlays: underlays, extraTarget: size == 8})
				f.releaseNodeCandidates()
				paths := f.plan.Paths[:size]
				f.plan.Paths = paths
				phases := []string{}
				complete := false
				defer func() {
					writeM3Report(t, filepath.Join(f.results, "node-lease.json"), map[string]any{"completed": complete && !t.Failed(), "placement": placement, "candidates": size, "phases": phases, "scope": "real mTLS, protected node candidates, new and existing TCP; no host suspend or application route activation"})
				}()
				for _, p := range paths {
					b := netOutput(t, f.robot, integrationBinary(t), "node", "relay", "prepare", "--config", f.node, "--path-id", p.PathID, "--probe-routes", "--lease")
					var out relayapply.Result
					if json.Unmarshal([]byte(b), &out) != nil || out.KernelReady || out.Reason != "lease_inactive" {
						t.Fatal("prepare opened lease", b)
					}
				}
				if f.probe(paths[0]).OK {
					t.Fatal("closed preparation passed packets")
				}
				phases = append(phases, "prepare_closed")
				start := func(label string) *networkProcess {
					return startNetworkProcess(t, f.robot, filepath.Join(f.results, label+"-supervisor.jsonl"), nil, integrationBinary(t), "node", "relay", "supervise", "--config", f.node, "--refresh-interval", "1s")
				}
				watch := start("initial")
				ready := func() {
					eventually(t, 20*time.Second, "all node candidates live", func() error {
						for _, p := range paths {
							if v := f.probe(p); !v.OK {
								return fmt.Errorf("%s: %+v", p.PathID, v)
							}
						}
						return nil
					})
				}
				ready()
				phases = append(phases, "fresh_approval_all_paths")
				stream := startNetworkProcess(t, f.robot, filepath.Join(f.results, "existing-tcp.jsonl"), []string{"VPNCTL_WORKER=lease-stream", "VPNCTL_PROBE_SOURCE=" + strings.TrimSuffix(paths[0].InnerAddress, "/32")}, f.worker, "-test.run=^TestNetworkWorker$")
				eventually(t, 3*time.Second, "existing TCP baseline", func() error {
					b, _ := os.ReadFile(stream.log)
					if !strings.Contains(string(b), `"ok":true`) {
						return fmt.Errorf("no echo")
					}
					return nil
				})
				paused := time.Now()
				if err := watch.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				time.Sleep(11 * time.Second)
				for _, p := range paths {
					if v := f.probe(p); v.OK {
						t.Fatal("SIGSTOP new TCP escaped", p.PathID, v)
					}
				}
				b, err := os.ReadFile(stream.log)
				if err != nil {
					t.Fatal(err)
				}
				failed := false
				for _, line := range strings.Split(string(b), "\n") {
					var event leaseStreamEvent
					if json.Unmarshal([]byte(line), &event) == nil && event.At.After(paused.Add(11*time.Second)) {
						if event.OK {
							t.Fatal("SIGSTOP existing TCP escaped")
						}
						failed = true
					}
				}
				if !failed {
					t.Fatal("no post-expiry existing TCP evidence")
				}
				phases = append(phases, "sigstop_blocks_new_and_existing_tcp")
				// Recovery/inspect cannot recreate a fresh approval from persisted time.
				watch.stop() // prescribed SIGKILL fault, after the SIGSTOP evidence above
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err = netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "inspect", "--config", f.node).CombinedOutput()
				cancel()
				if err == nil || f.probe(paths[0]).OK {
					t.Fatal("restart inspect revived lease")
				}
				watch = start("restarted")
				ready()
				phases = append(phases, "restart_fresh_approval_rearms")
				// Let the selector own the lock for a batch; it must maintain leases
				// cooperatively without changing the application target reservation.
				netOutput(t, f.robot, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app")
				netOutput(t, f.robot, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app", "--samples", "2", "--interval", "100ms")
				if size == 8 {
					netOutput(t, f.robot, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app2")
					netOutput(t, f.robot, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app2", "--samples", "2", "--interval", "100ms")
					phases = append(phases, "two_target_observation_and_quarantine")
					if placement == "separate" {
						checkNodeLeaseSlowProbes(t, f)
						phases = append(phases, "slow_probes_do_not_starve_any_kernel_lease")
					}
				}
				ready()
				phases = append(phases, "selector_and_target_reservation_coexist")
				killStream := startNodeLeaseStream(t, f, "kill")
				killAt := time.Now()
				watch.stop()
				time.Sleep(11 * time.Second)
				for _, p := range paths {
					if f.probe(p).OK {
						t.Fatal("SIGKILL did not expire", p.PathID)
					}
				}
				requireNodeBlocked(t, f, killStream, killAt.Add(11*time.Second))
				phases = append(phases, "sigkill_blocks_new_and_existing_tcp")
				for _, p := range paths {
					f.nodeCall("release", p.PathID)
				}
				netOutput(t, f.robot, integrationBinary(t), "node", "relay", "target", "inspect", "--config", f.node, "--target-id", "app")
				phases = append(phases, "release_preserves_target_quarantine")
				complete = true
			})
		}
	}
}

func checkNodeLeaseSlowProbes(t *testing.T, f *m3AuthorityFixture) {
	t.Helper()
	(relayUplink{relay: f.target}).nft(t, `table inet slow_node_target {
 chain input { type filter hook input priority -310; policy accept;
 ip daddr 198.18.0.2 tcp dport 9192 drop
 }
}`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	cmd := netCommand(ctx, f.robot, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", "app", "--samples", "2", "--interval", "100ms", "--probe-timeout", "2s")
	output, err := os.Create(filepath.Join(f.results, "slow-selection.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	samples := 0
	started := time.Now()
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blackholed target selected as healthy")
			}
			if samples < 5 || time.Since(started) < 8*time.Second {
				t.Fatal("slow probe workload not exercised", samples, time.Since(started))
			}
			netOutput(t, f.target, "nft", "delete", "table", "inet", "slow_node_target")
			writeM3Report(t, filepath.Join(f.results, "node-slow-probes.json"), map[string]any{"completed": !t.Failed(), "samples": samples, "duration_seconds": time.Since(started).Seconds(), "all_eight_kernel_leases_active": true})
			return
		default:
		}
		probeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		probe := netCommand(probeCtx, f.robot, f.worker, "-test.run=^TestNetworkWorker$")
		probe.Env = append(os.Environ(), "VPNCTL_WORKER=boot-guard-snapshot")
		b, err := probe.Output()
		stop()
		if err != nil {
			t.Fatal("guard sampling failed", err)
		}
		states := map[string]struct {
			State relayguard.State `json:"state"`
			Error string           `json:"error"`
		}{}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "BOOTTIME_GUARDS=") {
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "BOOTTIME_GUARDS=")), &states); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, p := range f.plan.Paths {
			state, ok := states[p.Pin.WGInterface]
			if !ok || state.Error != "" || !state.State.Active {
				t.Fatalf("probe starved lease %s: %+v", p.PathID, state)
			}
		}
		samples++
		time.Sleep(500 * time.Millisecond)
	}
}
