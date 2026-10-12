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
	"vpnctl/internal/relayplan"
)

func TestNodeLeaseRetainedGrantRequiresFinalKernelValidation(t *testing.T) {
	for _, scenario := range []string{"unchanged", "generation", "map", "program", "deadline", "blocked", "guard error", "clock error", "suspend", "clock reverse", "cancelled", "nft shortened"} {
		t.Run(scenario, func(t *testing.T) {
			observed, err := relayguard.Now()
			if err != nil {
				t.Fatal(err)
			}
			entry := Entry{Alias: "vpnctl:node:retention-test", LinkIndex: 123, LeaseVersion: 3, Phase: "prepared", ApprovalUntil: time.Now().Add(time.Minute), ApprovalBootNS: observed + uint64(time.Minute)}
			entry.Candidate.Pin = &relayplan.PinInput{WGInterface: "wgretain001"}
			de := nodeLeaseEntry(entry)
			deadline := time.Now().Add(9 * time.Second).Truncate(time.Second)
			first := relayguard.State{Active: true, ObservedNS: observed, DeadlineNS: observed + uint64(9*time.Second), Generation: 3, MapID: 4, ProgramID: 5}
			nftReads, guardReads, clockReads, writes := 0, 0, 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			readErr := errors.New("test read failed")
			k := nodeKernel{
				kernel: kernel{run: func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
					switch strings.Join(args, " ") {
					case "-j -n -T list flowtables":
						return json.Marshal(object{"nftables": []object{}})
					case "-j -n -T list table inet " + leaseTable(de):
						nftReads++
						rows := stagedLeaseTestRows(de, deadline, "lease_00000000000000000000000000000001", "")
						remaining := 9
						if scenario == "nft shortened" && nftReads == 2 {
							remaining = 1
						}
						rows[1]["set"].(object)["elem"] = []any{object{"elem": object{"val": de.LinkIndex, "expires": remaining}}}
						return json.Marshal(object{"nftables": rows})
					case "-f /dev/stdin":
						writes++
						return nil, errors.New("test forbids mutation")
					default:
						t.Fatal("unexpected kernel command")
						return nil, ErrConflict
					}
				}},
				readLeaseGuard: func(_ context.Context, owner relayguard.Owner) (relayguard.State, error) {
					guardReads++
					if owner != nodeGuardOwner(entry) {
						t.Fatal("read wrong owner")
					}
					b := first
					if guardReads == 2 {
						switch scenario {
						case "generation":
							b.Generation++
						case "map":
							b.MapID++
						case "program":
							b.ProgramID++
						case "deadline":
							b.DeadlineNS++
						case "blocked":
							b.Active = false
						case "guard error":
							return b, readErr
						case "cancelled":
							cancel()
						}
					}
					return b, nil
				},
				leaseClock: func() (time.Duration, error) {
					clockReads++
					if guardReads != 2 {
						t.Fatal("final clock captured before BPF readback")
					}
					switch scenario {
					case "clock error":
						return 0, readErr
					case "suspend":
						return time.Duration(observed) + 10*time.Second, nil
					case "clock reverse":
						return time.Duration(observed) - 1, nil
					case "nft shortened":
						return time.Duration(observed) + 3*time.Second, nil
					}
					return leaseBootTime()
				},
			}
			got, err := k.Lease(ctx, entry, FreshApproval{})
			if writes != 0 || guardReads != 2 || nftReads != 2 {
				t.Fatalf("wrong grant/readback path writes=%d guard=%d nft=%d", writes, guardReads, nftReads)
			}
			if scenario == "unchanged" {
				if err != nil || !got.Active || !got.Deadline.Equal(deadline) || got.Boot == nil || got.Boot.DeadlineNS != first.DeadlineNS || got.rearmed {
					t.Fatal("live grant changed", err)
				}
			} else if err == nil || got.Active {
				t.Fatal("accepted invalid final kernel state", scenario)
			}
			if scenario != "guard error" && clockReads != 1 {
				t.Fatal("missing final BOOTTIME read")
			}
		})
	}
}
