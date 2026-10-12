// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayguard"
)

func TestNodeLeaseRetainsLiveHeadroomWithoutMutation(t *testing.T) {
	entry := DeploymentEntry{
		Interface:    "wgretain001",
		Alias:        "vpnctl:node:retention-test",
		LinkIndex:    2147483647,
		Group:        2147483647,
		Phase:        "applied",
		LeaseVersion: 3,
	}
	observed, err := relayguard.Now()
	if err != nil {
		t.Fatal(err)
	}
	guard := relayguard.State{
		DeadlineNS: observed + uint64(9*time.Second),
		Generation: 7,
		ObservedNS: observed,
		MapID:      11,
		ProgramID:  13,
		Active:     true,
	}
	deadline := time.Now().Add(9 * time.Second).Truncate(time.Second)
	const selected = "lease_00000000000000000000000000000001"
	writeAttempt := errors.New("test forbids nft mutation")
	reads, flowtableReads, writes := 0, 0, 0
	k := deploymentKernel{kernel: kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		if name != "nft" {
			t.Fatal("unexpected non-nft lease command")
		}
		switch strings.Join(args, " ") {
		case "-j -n -T list flowtables":
			flowtableReads++
			return json.Marshal(object{"nftables": []object{}})
		case "-j -n -T list table inet " + leaseTable(entry):
			reads++
			rows := stagedLeaseTestRows(entry, deadline, selected, "")
			rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": entry.LinkIndex, "expires": 9}}}
			return json.Marshal(object{"nftables": rows})
		case "-f /dev/stdin":
			writes++
			// The existing renewal reaches this before relayguard.Update.
			// Reject it so this regression never reaches a real BPF mutation.
			return nil, writeAttempt
		default:
			t.Fatal("unexpected lease command")
			return nil, ErrConflict
		}
	}}}

	got, err := k.stagedLeaseBounded(context.Background(), entry, time.Now().Add(time.Minute), FreshApproval{}, &guard, observed+uint64(time.Minute))
	if writes != 0 {
		t.Errorf("live lease with sufficient headroom attempted %d nft mutations", writes)
	}
	if err != nil {
		t.Fatalf("retain existing live lease: %v", err)
	}
	if reads < 2 || flowtableReads == 0 {
		t.Fatalf("retain omitted live inventory or final readback: lease reads=%d, flowtable reads=%d", reads, flowtableReads)
	}
	if !got.Active || !got.Deadline.Equal(deadline) || got.set != selected || len(got.staged) != 0 || got.rearmed {
		t.Fatal("retain changed the existing grant or did not preserve its active state")
	}
}

func TestNodeLeaseRetentionDoesNotBypassRenewalOrRearmScope(t *testing.T) {
	for _, scenario := range []string{"v2", "missing BPF", "missing approval bound", "insufficient headroom", "shortened approval", "expired without fresh approval"} {
		t.Run(scenario, func(t *testing.T) {
			e := DeploymentEntry{Interface: "wgretain001", Alias: "vpnctl:node:retention-test", LinkIndex: 123, LeaseVersion: 3}
			observed, err := relayguard.Now()
			if err != nil {
				t.Fatal(err)
			}
			guard := &relayguard.State{Active: true, ObservedNS: observed, DeadlineNS: observed + uint64(9*time.Second), Generation: 3, MapID: 4, ProgramID: 5}
			expiry, bound := time.Now().Add(time.Minute), observed+uint64(time.Minute)
			countdown := 9
			switch scenario {
			case "v2":
				e.LeaseVersion = 2
			case "missing BPF":
				guard = nil
			case "missing approval bound":
				bound = 0
			case "insufficient headroom":
				countdown = 4
			case "shortened approval":
				expiry = time.Now().Add(7 * time.Second)
			case "expired without fresh approval":
				countdown = 0
				guard.Active = false
			}
			writes := 0
			writeAttempt := errors.New("test intercepted normal renewal")
			k := deploymentKernel{kernel: kernel{run: func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j -n -T list flowtables":
					return json.Marshal(object{"nftables": []object{}})
				case "-j -n -T list table inet " + leaseTable(e):
					rows := stagedLeaseTestRows(e, time.Now().Add(9*time.Second).Truncate(time.Second), "lease_00000000000000000000000000000001", "")
					rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": e.LinkIndex, "expires": countdown}}}
					return json.Marshal(object{"nftables": rows})
				case "-f /dev/stdin":
					writes++
					return nil, writeAttempt
				default:
					t.Fatal("unexpected command")
					return nil, ErrConflict
				}
			}}}
			_, err = k.stagedLeaseBounded(context.Background(), e, expiry, FreshApproval{}, guard, bound)
			if scenario == "expired without fresh approval" {
				if !errors.Is(err, ErrLeaseExpired) || writes != 0 {
					t.Fatal("cached approval rearmed expired lease", err, writes)
				}
			} else if !errors.Is(err, writeAttempt) || writes != 1 {
				t.Fatal("normal bounded renewal was bypassed", err, writes)
			}
		})
	}
}
