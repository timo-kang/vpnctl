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
	"vpnctl/internal/relaycatalog"
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
			for _, mark := range d.Checkpoints {
				if mark.Name == "ownership_release_started" || mark.Name == "ownership_release_finished" {
					t.Fatal("failed admission claimed ownership release")
				}
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

// Empty journals exercise real cache/FIFO/namespace ownership without changing
// host interfaces. Work errors must still report the entire release boundary.
func TestNodeCycleDiagnosticsIncludeOwnershipRelease(t *testing.T) {
	for _, entry := range []string{"observation", "reconcile", "supervisor"} {
		t.Run(entry, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "cache")
			seed, err := relaycache.Open(dir, relaycache.Options{NodeID: "robot", Create: true})
			if err != nil {
				t.Fatal(err)
			}
			seed.Close()
			node := &config.NodeConfig{Name: "robot"}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var d *relayobserve.Diagnostics
			switch entry {
			case "observation":
				out := collectTargetObservation(ctx, node, dir, "", "", time.Second)
				if out.Valid {
					t.Fatal("invalid request became valid")
				}
				d = out.Diagnostics
			case "reconcile":
				out, err := reconcileApplicationTarget(ctx, node, dir, "app", "", time.Second, nil)
				if err == nil || out.Applied {
					t.Fatal("invalid request was applied")
				}
				d = out.Diagnostics
			case "supervisor":
				out, _ := nodeSupervisionCycle(ctx, node, dir, nil, false)
				d = out.Diagnostics
			}
			if d == nil || !d.MonotonicAvailable || d.CheckpointsDropped {
				t.Fatal("missing complete monotonic diagnostics")
			}
			want := []string{"admission_queue_ready", "admission_cache_ready", "admission_kernel_ready"}
			if entry == "supervisor" {
				want = append(want, "supervision_maintenance_started", "supervision_maintenance_complete", "supervision_rebuild_complete")
			}
			want = append(want, "ownership_release_started", "ownership_release_finished")
			if len(d.Checkpoints) != len(want) {
				t.Fatalf("release boundaries missing: %+v", d.Checkpoints)
			}
			previous := d.StartedMono
			for i, checkpoint := range d.Checkpoints {
				if checkpoint.Name != want[i] || checkpoint.At < previous || checkpoint.At > d.FinishedMono {
					t.Fatal("incorrect release boundary", checkpoint)
				}
				previous = checkpoint.At
			}
			// The same cache/FIFO and namespace must be reusable before return.
			c, e, err := openNodeRelayEngine(ctx, node, dir)
			if err != nil {
				t.Fatal("cycle retained ownership", err)
			}
			e.Close()
			c.Close()
		})
	}
}

type releaseBoundaryClient struct{ entered chan struct{} }

func (c releaseBoundaryClient) RelayCatalog(ctx context.Context, _ string) (relaycatalog.View, error) {
	close(c.entered)
	<-ctx.Done()
	return relaycatalog.View{}, ctx.Err()
}
func (releaseBoundaryClient) BindRelayPath(context.Context, relaycatalog.BindRequest) (relaycatalog.View, error) {
	return relaycatalog.View{}, errors.New("unexpected bind")
}

func TestNodeReleaseBoundaryWaitsForCacheClose(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "cache")
	seed, err := relaycache.Open(dir, relaycache.Options{NodeID: "robot", Create: true})
	if err != nil {
		t.Fatal(err)
	}
	seed.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, recorder := relayobserve.Start(ctx)
	c, e, err := openNodeRelayEngine(ctx, &config.NodeConfig{Name: "robot"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	client := releaseBoundaryClient{entered: make(chan struct{})}
	refreshed, closed := make(chan struct{}), make(chan struct{})
	go func() { defer close(refreshed); _, _ = c.Refresh(ctx, client) }()
	select {
	case <-client.entered:
	case <-ctx.Done():
		<-refreshed
		e.Close()
		c.Close()
		t.Fatal("refresh did not acquire cache mutex")
	}
	go func() { defer close(closed); closeNodeRelayEngine(ctx, c, e) }()
	defer func() { cancel(); <-refreshed; <-closed }()
	// The real Store.Close waits for Refresh to release the cache mutex. Keep
	// that barrier closed while checking that release-finished is not emitted.
	for {
		seen := false
		for _, mark := range recorder.Snapshot().Checkpoints {
			if mark.Name == "ownership_release_started" {
				seen = true
			}
		}
		if seen {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("release did not start")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-closed:
		t.Fatal("cache closed while refresh retained its mutex")
	case <-time.After(20 * time.Millisecond):
	}
	for _, mark := range recorder.Snapshot().Checkpoints {
		if mark.Name == "ownership_release_finished" {
			t.Fatal("release completed before cache close")
		}
	}
	cancel()
	<-closed
	marks := recorder.Snapshot().Checkpoints
	if marks[len(marks)-1].Name != "ownership_release_finished" {
		t.Fatal("canceled context lost completed release")
	}
}
