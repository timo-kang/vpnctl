//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
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

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

func checkM3ConcurrentRecipients(t *testing.T, ctrl *m3Controller, first *m3Recipient, spec relaycatalog.Spec) map[string]any {
	t.Helper()
	key, pub := wgKeyPair(t)
	keyfile := filepath.Join(ctrl.private, "second.key")
	mustWrite(t, keyfile, key)
	secondRelay := relaycatalog.Relay{ID: "second", PublicKey: pub, KeyGeneration: 1}
	for ep := 0; ep < 8; ep++ {
		secondRelay.Endpoints = append(secondRelay.Endpoints, relaycatalog.Endpoint{ID: fmt.Sprintf("ep%d", ep), Address: fmt.Sprintf("192.0.2.2:%d", 52820+ep)})
	}
	spec.Relays = append(spec.Relays, secondRelay)
	ctrl.apply(spec, 3600)
	ctrl.grant("second", "node-0")
	// Build the second deployment in a maintenance window. Fair acquisition
	// by a CLI is not promised while two long supervisor cycles hold caches.
	first.watch.terminate(t)
	second := &m3Recipient{t: t, ns: first.ns, config: first.config, relay: "second", cache: filepath.Join(ctrl.private, "second-cache"), key: keyfile, results: ctrl.results, generation: 1}
	second.require("refresh", -1, 0)
	for ep := 0; ep < 8; ep++ {
		second.require("apply", ep, 52820+ep)
		if ep == 0 {
			second.start()
			// Cross the initial five-second grant while setup is still in progress.
			// The supervisor must keep the first endpoint live for later Apply inspection.
			time.Sleep(6 * time.Second)
		}
	}
	second.ready()
	second.watch.terminate(t)
	// Reproduce CI's >1s cycle even on a fast host. A zero-idle supervisor
	// used to reacquire the namespace repeatedly, starving its competitor.
	slow := filepath.Join(ctrl.private, "slow-supervisor")
	if err := os.Mkdir(slow, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(slow, "invocations")
	script := "#!/bin/sh\nprintf . >> '" + marker + "'\nsleep 0.01\nexec /usr/sbin/nft \"$@\"\n"
	if err := os.WriteFile(filepath.Join(slow, "nft"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	second.start("PATH=" + slow + ":" + os.Getenv("PATH"))
	second.ready()
	first.start()
	first.ready()
	second.ready()
	first.ready()
	type result struct {
		action string
		err    error
	}
	out := make(chan result, 60)
	started := time.Now()
	for _, action := range []string{"refresh", "apply", "release", "malformed"} {
		go func(action string) {
			for attempt := 0; attempt < 12; attempt++ {
				var err error
				switch action {
				case "refresh":
					_, err = first.call(action, -1, 0)
				case "malformed":
					_, err = second.call("apply", 99, 52999)
				default:
					_, err = second.call(action, 7, 52827)
				}
				out <- result{action, err}
			}
		}(action)
	}
	success, busy, rejected := map[string]int{"refresh": 0, "apply": 0, "release": 0}, map[string]int{"refresh": 0, "apply": 0, "release": 0}, 0
	for i := 0; i < 48; i++ {
		r := <-out
		if r.action == "malformed" {
			if r.err == nil {
				t.Fatal("unknown endpoint accepted")
			}
			rejected++
			continue
		}
		if r.err == nil {
			success[r.action]++
			continue
		}
		var exit *exec.ExitError
		if errors.As(r.err, &exit) && (strings.Contains(string(exit.Stderr), "busy") || strings.Contains(string(exit.Stderr), "another process owns")) {
			busy[r.action]++
			continue
		}
		t.Fatalf("unexpected concurrent %s failure: %v", r.action, r.err)
	}
	// Locks are deliberately fail-fast, not fair queues. Per-operation success
	// may be zero during the burst; preserve those counts as availability loss.
	// Successful setup and explicit recovery verify every mutation separately.
	if busy["refresh"]+busy["apply"]+busy["release"] == 0 {
		t.Fatal("no lock contention observed")
	}
	// Both supervisors ran throughout the concurrent burst. Stop them for
	// explicit operator recovery; never mistake fail-fast CLI starvation for
	// a promise of fair queuing. Preserve the observed zero-success counts.
	first.watch.terminate(t)
	second.watch.terminate(t)
	log, err := os.ReadFile(second.watch.log)
	if err != nil {
		t.Fatal(err)
	}
	var overrunCycles int
	var maxCycle int64
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		var report m3SupervisorReport
		if err := json.Unmarshal([]byte(line), &report); err != nil {
			t.Fatal(err)
		}
		if report.CycleMS > 1000 {
			overrunCycles++
		}
		if report.CycleMS > maxCycle {
			maxCycle = report.CycleMS
		}
	}
	invocations, err := os.ReadFile(marker)
	if err != nil || len(invocations) == 0 || overrunCycles == 0 || maxCycle > 5500 {
		t.Fatal("overrunning supervisor injection not exercised within budget", overrunCycles, maxCycle, err)
	}
	if _, err := second.call("apply", 99, 52999); err == nil {
		t.Fatal("invalid endpoint accepted without contention")
	}
	second.require("apply", 7, 52827)
	second.start()
	if out := second.ready(); len(out.Kernel.Endpoints) != 8 {
		t.Fatal("second deployment not restored", out)
	}
	second.watch.terminate(t)
	for ep := 0; ep < 8; ep++ {
		second.require("release", ep, 0)
	}
	first.start()
	first.ready()
	return map[string]any{"attempts": 48, "successful": success, "busy_rejections": busy, "malformed_rejected": rejected, "invalid_endpoint_rejected_without_contention": true, "maintenance_pauses_for_setup_and_recovery": true, "delayed_supervisor": map[string]any{"nft_delay_ms": 10, "invocations": len(invocations), "over_1s_cycles": overrunCycles, "max_cycle_ms": maxCycle}, "duration_ms": time.Since(started).Milliseconds(), "relay_caches": 2, "namespace_count": 1, "installed_endpoints_before": 16, "real_peers": 128}
}

func checkM3InterruptedApproval(t *testing.T, r *m3Recipient) map[string]any {
	t.Helper()
	r.watch.terminate(t)
	(relayUplink{relay: r.ns}).nft(t, `table inet interrupted_outage {
 chain output { type filter hook output priority -310; policy accept;
 ip daddr 192.0.2.1 tcp dport 9443 counter drop
 }
}`)
	r.start()
	readProgress := func() bool {
		b, err := os.ReadFile(filepath.Join(r.cache, "state.json"))
		if err != nil {
			return false
		}
		var state struct {
			Refresh struct {
				Result string `json:"result"`
			} `json:"refresh"`
		}
		return json.Unmarshal(b, &state) == nil && state.Refresh.Result == "in_progress"
	}
	eventually(t, 5*time.Second, "persisted in-progress refresh", func() error {
		if !readProgress() {
			return fmt.Errorf("not in progress")
		}
		return nil
	})
	if err := r.watch.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	if !readProgress() {
		t.Fatal("refresh completed before interruption; injection not proven")
	}
	r.watch.stop()
	b, err := r.call("status", -1, 0)
	var status relaycache.DeploymentReport
	if err != nil || json.Unmarshal(b, &status) != nil || status.ApprovalValid || status.BlockedReason != "refresh_interrupted" {
		t.Fatal("interrupted approval accepted", err, string(b))
	}
	r.start()
	eventually(t, 10*time.Second, "interrupted approval kernel cleanup", func() error {
		if netOutput(t, r.ns, "wg", "show", "interfaces") != "" {
			return fmt.Errorf("peers remain")
		}
		return nil
	})
	r.watch.terminate(t)
	netOutput(t, r.ns, "nft", "delete", "table", "inet", "interrupted_outage")
	r.require("refresh", -1, 0)
	// A stop can land after the last link deletion but before the guard/journal
	// cleanup commit. Finish that recorded operation before reinstalling.
	if got := netOutput(t, r.ns, "wg", "show", "interfaces"); got != "" {
		t.Fatal("fresh response unexpectedly installed peers", got)
	}
	r.require("recover", -1, 0)
	if out := r.require("inspect", -1, 0); out.State != "empty" || len(out.Endpoints) != 0 {
		t.Fatal("refresh unexpectedly installed peers", out)
	}
	for ep := 0; ep < 8; ep++ {
		r.require("apply", ep, 51820+ep)
		if ep == 0 {
			r.start()
		}
	}
	r.ready()
	return map[string]any{"persisted_in_progress_proven": true, "approval_after_interrupt": status, "all_endpoints_removed_during_outage": true, "fresh_response_alone_did_not_install": true, "explicit_recover_completed_cleanup": true, "explicit_key_checked_reinstall": true}
}
