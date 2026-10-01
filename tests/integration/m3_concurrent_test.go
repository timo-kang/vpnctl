//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	second := &m3Recipient{t: t, ns: first.ns, config: first.config, relay: "second", cache: filepath.Join(ctrl.private, "second-cache"), key: keyfile, results: ctrl.results, generation: 1}
	second.require("refresh", -1, 0)
	for ep := 0; ep < 8; ep++ {
		second.require("apply", ep, 52820+ep)
		if ep == 0 {
			second.start()
		}
	}
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
	success, busy, rejected := map[string]int{}, map[string]int{}, 0
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
	second.require("apply", 7, 52827)
	second.ready()
	first.ready()
	second.watch.stop()
	for ep := 0; ep < 8; ep++ {
		second.require("release", ep, 0)
	}
	first.ready()
	return map[string]any{"attempts": 48, "successful": success, "busy_rejections": busy, "malformed_rejected": rejected, "duration_ms": time.Since(started).Milliseconds(), "relay_caches": 2, "namespace_count": 1, "installed_endpoints_before": 16, "real_peers": 128}
}
