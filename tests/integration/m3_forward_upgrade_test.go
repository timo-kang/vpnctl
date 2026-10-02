//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetns_M3ForwardPolicyUpgrade(t *testing.T) {
	requireNetwork(t)
	previous := os.Getenv("VPNCTL_TEST_PREVIOUS_BINARY")
	if previous == "" {
		t.Skip("provide the pinned pre-policy Linux binary with VPNCTL_TEST_PREVIOUS_BINARY")
	}
	f := newM3AuthorityFixture(t)
	for _, r := range f.recipients {
		r.watch.terminate(t)
	}
	for _, r := range f.recipients {
		before, err := os.ReadFile(filepath.Join(r.cache, "peers.json"))
		if err != nil || !bytes.Contains(before, []byte(`"policy_version":1`)) {
			t.Fatal("new policy journal missing", err)
		}
		links := netOutput(t, r.ns, "ip", "-j", "link", "show")
		a := r.args("inspect", "")
		a[0] = previous
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		b, err := netCommand(ctx, r.ns, a...).CombinedOutput()
		cancel()
		after, readErr := os.ReadFile(filepath.Join(r.cache, "peers.json"))
		if err == nil || readErr != nil || !bytes.Equal(before, after) || links != netOutput(t, r.ns, "ip", "-j", "link", "show") {
			t.Fatal("old binary accepted or mutated new policy", err, string(b))
		}
		for ep := 0; ep < 2; ep++ {
			r.require("release", ep, 0)
		}
		r.cache = filepath.Join(f.private, "before-policy-"+r.relay)
		r.require("refresh", -1, 0)
		for ep := 0; ep < 2; ep++ {
			a = r.args("apply", fmt.Sprintf("ep%d", ep))
			a[0] = previous
			a = append(a, "--key-file", r.key, "--key-generation", "1", "--listen-port", fmt.Sprint(51820+ep))
			ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
			b, err = netCommand(ctx, r.ns, a...).CombinedOutput()
			cancel()
			if err != nil {
				t.Fatal("old binary installation", err, string(b))
			}
		}
		old, err := os.ReadFile(filepath.Join(r.cache, "peers.json"))
		if err != nil || bytes.Contains(old, []byte(`"policy_version"`)) || !bytes.Contains(old, []byte(`"lease_version":3`)) || len(strings.Fields(netOutput(t, r.ns, "wg", "show", "interfaces"))) != 2 {
			t.Fatal("fixture is not pre-policy BOOTTIME installation", err)
		}
		r.start()
		eventually(t, 10*time.Second, "upgrade quiesces pre-policy peers", func() error {
			if netOutput(t, r.ns, "wg", "show", "interfaces") != "" {
				return fmt.Errorf("legacy interfaces remain")
			}
			return nil
		})
		r.watch.terminate(t)
		r.require("refresh", -1, 0)
		r.require("recover", -1, 0)
		if v := r.require("inspect", -1, 0); v.State != "empty" {
			t.Fatal("upgrade silently adopted old authorization", v)
		}
	}
	f.releaseNodeCandidates()
	f.install()
	for _, p := range f.plan.Paths {
		eventually(t, 10*time.Second, "fresh policy traffic "+p.PathID, func() error {
			if !f.probe(p).OK {
				return fmt.Errorf("not restored")
			}
			return nil
		})
	}
	writeM3Report(t, filepath.Join(f.results, "policy-upgrade.json"), map[string]any{"completed": true, "old_binary_rejected_new_journal": true, "old_lease_v3_removed": true, "fresh_explicit_policy_apply_restored_four_paths": true})
}
