// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relayobserve"
)

func TestNodeAdmissionDiagnosticsReachFailedReports(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "cache")
	holder, err := relaycache.Open(dir, relaycache.Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	node := &config.NodeConfig{Name: "robot"}
	for _, entry := range []string{"observation", "reconcile", "supervisor"} {
		t.Run(entry, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
			defer cancel()
			var d *relayobserve.Diagnostics
			switch entry {
			case "observation":
				out := collectTargetObservation(ctx, node, dir, "app", "", time.Second)
				if out.Valid || len(out.Paths) != 0 || out.Reason != "cache_unavailable" {
					t.Fatal("failed admission supplied an observation")
				}
				d = out.Diagnostics
			case "reconcile":
				out, err := reconcileApplicationTarget(ctx, node, dir, "app", "", time.Second, nil)
				if !errors.Is(err, context.DeadlineExceeded) || out.Applied || out.Selection.Reason != "ownership_unavailable" || out.Application.State != "blocked" {
					t.Fatal("failed admission changed route status", err)
				}
				d = out.Diagnostics
			case "supervisor":
				out, err := nodeSupervisionCycle(ctx, node, dir, nil, true)
				if !errors.Is(err, context.DeadlineExceeded) || out.Kernel != nil || out.Refresh != "not_due" || out.State != "blocked" {
					t.Fatal("failed admission started supervised work", err)
				}
				d = out.Diagnostics
			}
			if d == nil || d.Phases["admission"].Calls != 1 || d.Phases["admission_queue"].Calls != 1 || d.Phases["admission_cache"].Calls != 1 || d.Phases["admission_cache"].Duration < 70*time.Millisecond || d.Phases["admission_kernel"].Calls != 0 {
				t.Fatalf("missing/incorrect admission attribution: %+v", d)
			}
		})
	}
}

// Opening an empty/corrupt journal only holds an advisory Unix socket and reads
// the private cache. No interfaces, routes, peers or kernel policies are read or
// changed. A second independent cache exercises namespace-only contention.
func TestNodeAdmissionKernelDiagnostics(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	node := &config.NodeConfig{Name: "robot"}
	for _, mode := range []string{"ready", "invalid_journal", "busy"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(root, mode)
			seed, err := relaycache.Open(dir, relaycache.Options{NodeID: "robot", Create: true})
			if err != nil {
				t.Fatal(err)
			}
			defer seed.Close()
			if mode == "invalid_journal" {
				if err := seed.SaveApplyJournal([]byte("{")); err != nil {
					t.Fatal(err)
				}
			}
			seed.Close()
			if mode == "busy" {
				ownerDir := filepath.Join(root, "namespace-owner")
				owner, err := relaycache.Open(ownerDir, relaycache.Options{NodeID: "robot", Create: true})
				if err != nil {
					t.Fatal(err)
				}
				owner.Close()
				c, e, err := openNodeRelayEngine(context.Background(), node, ownerDir)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				defer e.Close()
			}
			limit := time.Second
			if mode == "busy" {
				limit = 75 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			ctx, recorder := relayobserve.Start(ctx)
			c, e, err := openNodeRelayEngine(ctx, node, dir)
			if c != nil {
				defer c.Close()
			}
			if e != nil {
				defer e.Close()
			}
			if mode == "ready" {
				if err != nil || c == nil || e == nil {
					t.Fatal("empty engine did not open", err)
				}
			} else if err == nil || c != nil || e != nil || mode == "busy" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("failed engine opening retained ownership", err)
			}
			d := recorder.Snapshot()
			if d.Phases["admission_kernel"].Calls != 1 || d.Phases["admission_kernel"].Duration <= 0 {
				t.Fatal("kernel opening cost missing", d.Phases)
			}
			if mode == "busy" && d.Phases["admission_kernel"].Duration < 70*time.Millisecond {
				t.Fatal("namespace wait attributed elsewhere", d.Phases)
			}
			want := []string{"admission_queue_ready", "admission_cache_ready"}
			if mode == "ready" {
				want = append(want, "admission_kernel_ready")
			}
			if len(d.Checkpoints) != len(want) {
				t.Fatal("incorrect readiness boundaries", d.Checkpoints)
			}
			for i, checkpoint := range d.Checkpoints {
				if checkpoint.Name != want[i] {
					t.Fatal("incorrect readiness order", d.Checkpoints)
				}
			}
		})
	}
}
