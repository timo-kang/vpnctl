//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayguard"
	"vpnctl/internal/relayselect"
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
				nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app")
				checkNodeLeaseSelection(t, f, "app")
				if size == 8 {
					nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "reserve", "--config", f.node, "--target-id", "app2")
					checkNodeLeaseSelection(t, f, "app2")
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
				nodeAdmissionOutput(t, f, integrationBinary(t), "node", "relay", "target", "inspect", "--config", f.node, "--target-id", "app")
				phases = append(phases, "release_preserves_target_quarantine")
				complete = true
			})
		}
	}
}

func checkNodeLeaseSelection(t *testing.T, f *m3AuthorityFixture, target string) {
	t.Helper()
	// A lock admission failure is not a completed observation. Keep the same
	// selector alive until two fresh confirmations exist for every candidate.
	started := time.Now()
	logfile := filepath.Join(f.results, "node-selection-"+target+".jsonl")
	watch := startNetworkProcess(t, f.robot, logfile, nil, integrationBinary(t), "node", "relay", "select", "--config", f.node, "--target-id", target, "--watch", "--interval", "500ms")
	var decision relayselect.Decision
	count := 0
	eventually(t, 90*time.Second, "all candidates freshly confirmed ("+logfile+")", func() error {
		b, err := os.ReadFile(logfile)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		count = 0
		for _, line := range lines[:len(lines)-1] {
			if err := json.Unmarshal([]byte(line), &decision); err != nil {
				return err
			}
			count++
		}
		if count < 2 || decision.Applied || decision.DesiredPathID == "" || decision.TargetID != target {
			return fmt.Errorf("selection incomplete: %s", decision.Reason)
		}
		prepared := make(map[string]bool, len(f.plan.Paths))
		for _, path := range f.plan.Paths {
			prepared[path.PathID] = true
		}
		if !prepared[decision.DesiredPathID] {
			return fmt.Errorf("unprepared path selected: %s", decision.DesiredPathID)
		}
		for _, candidate := range decision.Candidates {
			if !prepared[candidate.PathID] {
				if candidate.Eligible {
					return fmt.Errorf("unprepared path eligible: %s", candidate.PathID)
				}
				continue
			}
			if candidate.State != "reachable" || !candidate.Eligible {
				return fmt.Errorf("%s not confirmed: %s", candidate.PathID, candidate.Exclusion)
			}
			delete(prepared, candidate.PathID)
		}
		if len(prepared) != 0 {
			return fmt.Errorf("missing prepared candidate observations: %v", prepared)
		}
		return nil
	})
	watch.terminate(t)
	for _, path := range f.plan.Paths {
		found := false
		for _, candidate := range decision.Candidates {
			if candidate.PathID == path.PathID {
				found = true
				if candidate.State != "reachable" || !candidate.Eligible {
					t.Fatal("prepared candidate not confirmed", candidate)
				}
			}
		}
		if !found {
			t.Fatal("missing prepared candidate", path.PathID)
		}
	}
	writeM3Report(t, filepath.Join(f.results, "node-selection-"+target+".json"), map[string]any{"completed": !t.Failed(), "duration_seconds": time.Since(started).Seconds(), "samples": count, "prepared_candidates": len(f.plan.Paths), "decision": decision})
}

func checkNodeLeaseSlowProbes(t *testing.T, f *m3AuthorityFixture) {
	checkProtectedSlowProbes(t, f, false)
}
func checkProtectedSlowProbes(t *testing.T, f *m3AuthorityFixture, apply bool) {
	t.Helper()
	(relayUplink{relay: f.target}).nft(t, `table inet slow_node_target {
 chain input { type filter hook input priority -310; policy accept;
 ip daddr 198.18.0.2 tcp dport 9192 counter drop
 }
}`)
	budget := 50 * time.Second
	if apply {
		// Include admission retries without changing the product's one-second
		// lock or twenty-second observation budgets. Busy is not proof of
		// quarantine and must not count as a completed slow observation.
		budget = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	args := []string{integrationBinary(t), "node", "relay", "select"}
	if apply {
		args = []string{integrationBinary(t), "node", "relay", "target", "reconcile"}
	}
	args = append(args, "--config", f.node, "--target-id", "app", "--probe-timeout", "2s")
	if apply {
		args = append(args, "--watch", "--interval", "2s")
	} else {
		args = append(args, "--samples", "2", "--interval", "100ms")
	}
	cmd := netCommand(ctx, f.robot, args...)
	output, err := os.Create(filepath.Join(f.results, "slow-selection.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stderr, err := os.Create(filepath.Join(f.results, "slow-selection.stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd.Stdout = output
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	samples := 0
	started := time.Now()
	stopping := false
	completedApplications := func(data []byte) (negative, busy int) {
		t.Helper()
		lines := strings.Split(string(data), "\n")
		// The running encoder can have an incomplete final line.
		for _, line := range lines[:len(lines)-1] {
			var result relayapply.TargetReconcileResult
			if json.Unmarshal([]byte(line), &result) != nil || result.Applied || result.Selection.Applied || result.Application.Activated || result.Selection.DesiredPathID != "" || result.Selection.TargetID != "app" || result.Selection.SchemaVersion != 1 || result.Selection.Error() == nil {
				t.Fatal("invalid slow application decision", line)
			}
			if result.Selection.Reason == "ownership_unavailable" {
				if result.Application.Guarded || result.Application.Reason != "ownership_unavailable" {
					t.Fatal("busy admission claimed quarantine", line)
				}
				busy++
				continue
			}
			if !result.Application.Guarded {
				t.Fatal("slow apply escaped quarantine", line)
			}
			negative++
		}
		return
	}
	for {
		select {
		case err := <-done:
			var exit *exec.ExitError
			if ctx.Err() != nil || apply && (!stopping || err != nil) || !apply && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
				t.Fatal("selector did not finish with a bounded negative decision", err, ctx.Err())
			}
			if samples < 5 || time.Since(started) < 8*time.Second {
				t.Fatal("slow probe workload not exercised", samples, time.Since(started))
			}
			b, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			negative, busy := 0, 0
			if apply {
				negative, busy = completedApplications(b)
				if negative < 2 || negative+busy != len(lines) {
					t.Fatal("missing completed slow application observations", string(b))
				}
			} else if len(lines) != 2 {
				t.Fatal("missing slow observation decisions", string(b))
			}
			for _, line := range lines {
				if apply {
					break
				}
				var decision relayselect.Decision
				if err := json.Unmarshal([]byte(line), &decision); err != nil {
					t.Fatal(err)
				}
				if decision.SchemaVersion != 1 || decision.TargetID != "app" || decision.Applied || decision.DesiredPathID != "" || decision.Error() == nil {
					t.Fatal("invalid slow observation decision", line)
				}
				negative++
			}
			counter := netOutput(t, f.target, "nft", "list", "table", "inet", "slow_node_target")
			if !strings.Contains(counter, "counter packets ") || strings.Contains(counter, "counter packets 0 bytes 0") {
				t.Fatal("target blackhole did not receive packets")
			}
			netOutput(t, f.target, "nft", "delete", "table", "inet", "slow_node_target")
			writeM3Report(t, filepath.Join(f.results, "node-slow-probes.json"), map[string]any{"completed": !t.Failed(), "samples": samples, "duration_seconds": time.Since(started).Seconds(), "all_eight_kernel_leases_active": true, "negative_decisions": negative, "busy_admissions": busy, "blackhole_packets_observed": true, "application_reconcile": apply, "second_app_payload_verified": apply})
			return
		default:
		}
		if apply && !stopping {
			b, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if negative, _ := completedApplications(b); negative >= 2 {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal("stop completed slow workload", err)
				}
				stopping = true
			}
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
		if apply {
			if p := applicationPayload(t, f, "198.18.0.3"); !p.OK {
				t.Fatal("slow target starved second app", p)
			}
		}
		samples++
		time.Sleep(500 * time.Millisecond)
	}
}
