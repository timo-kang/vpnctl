// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"vpnctl/internal/relaycatalog"
)

func TestTargetRouteLookupGuardsBothSidesOfTCP(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	target := entry.Candidate.Targets[0]
	for _, failAt := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			lookups, reads, transfers := 0, 0, 0
			dialed := false
			failure := errors.New("route changed")
			k := kernel{
				targetLookup: func(ctx context.Context, got Entry, gotTarget relaycatalog.Target) error {
					lookups++
					if got.LinkIndex != entry.LinkIndex || gotTarget.ProbeAddress != target.ProbeAddress {
						t.Fatal("lookup lost candidate identity")
					}
					if lookups == failAt {
						return failure
					}
					return ctx.Err()
				},
				run: func(_ context.Context, _, name string, args ...string) ([]byte, error) {
					if name != "wg" {
						t.Fatalf("unexpected external process %s", name)
					}
					reads++
					if len(args) != 3 || args[2] != "dump" {
						t.Fatal("unexpected counter query")
					}
					transfers++
					return counterSnapshotWire(entry, "1", fmt.Sprint(100*transfers), fmt.Sprint(100*transfers)), nil
				},
			}
			proof, err := k.probeTargetWithDial(context.Background(), entry, target, func(context.Context, Entry, relaycatalog.Target) (net.Conn, error) {
				dialed = true
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			})
			if failAt != 0 {
				if !errors.Is(err, failure) || proof != (targetProof{}) {
					t.Fatal("route failure became a successful proof", proof, err)
				}
			} else if err != nil || proof.rx == 0 || proof.tx == 0 || lookups != 2 || reads != 2 {
				t.Fatal("successful proof omitted live evidence", proof, err, lookups, reads)
			}
			if failAt == 1 && (dialed || reads != 0) {
				t.Fatal("TCP or counters started without route evidence")
			}
			if failAt == 2 && (!dialed || lookups != 2 || reads != 1) {
				t.Fatal("post-TCP route check skipped")
			}
		})
	}
}
