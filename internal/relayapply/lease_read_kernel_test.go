//go:build linux

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"
)

// Combining the exact-table and global flowtable reads can narrow libnftables'
// cache to the selected table (reproduced with nft 1.0.6). Exercise the production
// guard against real foreign flowtables, not a fake that assumes global scope.
func TestLiveLeaseReadGlobalFlowtables(t *testing.T) {
	for _, family := range []string{"inet", "ip", "ip6"} {
		t.Run(family, func(t *testing.T) {
			entry, _, _ := routeQueryKernelFixture(t)
			ctx := context.Background()
			k := deploymentKernel{kernel: kernel{run: command}}
			e := DeploymentEntry{Interface: entry.Candidate.Pin.WGInterface,
				LinkIndex: entry.LinkIndex, Alias: "vpnctl-lease-query-fixture", LeaseVersion: 2}
			nft := func(script string) {
				t.Helper()
				if _, err := command(ctx, script, "nft", "-f", "/dev/stdin"); err != nil {
					t.Fatal("synthetic nft fixture command failed")
				}
			}
			version, err := command(ctx, "", "nft", "--version")
			if err != nil {
				t.Fatal("nft version unavailable")
			}
			t.Logf("nft_version=%s", regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`).Find(version))
			if err := k.stagedLeaseCreate(ctx, e); err != nil {
				t.Fatal("owned lease fixture creation failed")
			}
			t.Cleanup(func() { nft("delete table inet " + leaseTable(e) + "\n") })
			nft("create table " + family + " unrelated\n")
			t.Cleanup(func() { nft("delete table " + family + " unrelated\n") })
			assertStatus := func(wantSuccess bool) {
				t.Helper()
				state, err := k.LeaseStatus(ctx, e)
				if (err == nil) != wantSuccess {
					t.Fatalf("lease status success=%t, want=%t", err == nil, wantSuccess)
				}
				// The fixture's timer starts empty. Queries cannot grant a lease.
				if state.Active {
					t.Fatal("query activated an empty lease")
				}
			}
			assertStatus(true) // An unrelated ordinary table is allowed.
			// Read, add, read, remove, read, add, read: a previous healthy result
			// must not hide a new flowtable at a later validation boundary.
			for range 2 {
				nft(fmt.Sprintf("add flowtable %s unrelated ftprobe { hook ingress priority 0; devices = { %s }; }\n", family, e.Interface))
				assertStatus(false)
				now := time.Now()
				if _, err := k.Lease(ctx, e, now.Add(time.Minute), FreshApproval{At: now}); err == nil {
					t.Fatal("granted a lease with a foreign flowtable present")
				}
				nft("delete flowtable " + family + " unrelated ftprobe\n")
				assertStatus(true)
			}
		})
	}
}
