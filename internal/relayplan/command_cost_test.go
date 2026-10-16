// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"vpnctl/internal/relayobserve"
)

func TestInventoryCommandRetainsChildCPUAndParentAttribution(t *testing.T) {
	t.Setenv("VPNCTL_COST_DETAILS", "1")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\nprintf '[]'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	ctx, r := relayobserve.Start(context.Background())
	ctx, done := relayobserve.Phase(ctx, "maintenance")
	work, end := relayobserve.Detail(ctx, "maintenance_plan")
	if b, err := readIP(work, "-j", "address", "show"); err != nil || string(b) != "[]" {
		t.Fatal(string(b), err)
	}
	// PATH now contains only our fixture; removal makes the next start fail.
	if err := os.Remove(filepath.Join(dir, "ip")); err != nil {
		t.Fatal(err)
	}
	if _, err := readIP(work, "-j", "address", "show"); err == nil {
		t.Fatal("missing executable succeeded")
	}
	end()
	done()
	d := r.Snapshot()
	p := d.Details.Commands["maintenance/maintenance_plan/ip"]
	if p.Calls != 2 || p.CPUAvailable != 1 || p.CPUUnavailable != 1 || p.Wall <= 0 {
		t.Fatal(p)
	}
	if d.Phases["maintenance"].InventoryCommands != 2 || d.Details.Steps["maintenance_plan"].InventoryCommands != 2 {
		t.Fatal(d)
	}
}
