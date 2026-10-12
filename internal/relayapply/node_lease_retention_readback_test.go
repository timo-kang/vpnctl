// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"errors"
	"testing"
	"time"

	"vpnctl/internal/relayguard"
)

func TestIndependentRetentionHonorsShortenedReadbackTimer(t *testing.T) {
	wall := time.Unix(2000000000, 0)
	initial := DeploymentLease{Active: true, Deadline: wall.Add(9 * time.Second), nftRemaining: 9 * time.Second}
	first := relayguard.State{Active: true, ObservedNS: uint64(time.Second), DeadlineNS: uint64(10 * time.Second), Generation: 7, MapID: 11, ProgramID: 13}
	approval := wall.Add(time.Minute)
	approvalBoot := uint64(60 * time.Second)
	retained, err := planNodeLeaseRetention(initial, first, approval, approvalBoot, wall, 2*time.Second)
	if err != nil || retained == nil {
		t.Fatal("fixture did not qualify for retention")
	}
	// At BOOTTIME 2s the final nft readback sees the same selected set,
	// rules, and owner, but a replacement element now expires in 1s.
	// The BPF read takes 2s, so that nft element is already gone at 4s.
	latest := initial
	latest.nftRemaining = time.Second
	latest.retained = retained
	last := first
	last.ObservedNS = uint64(4 * time.Second)
	err = validateNodeLeaseRetention(latest, last, approval, approvalBoot, wall.Add(2*time.Second), 4*time.Second)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("accepted a readback timer that expired before final BPF validation: err=%v", err)
	}
}
