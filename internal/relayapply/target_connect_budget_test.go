// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycatalog"
)

func TestCandidateDialBudgetPreservesSurroundingEvidence(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	target := entry.Candidate.Targets[0]
	for _, tc := range []struct {
		name                             string
		limit, dialTime, parent, elapsed time.Duration
		success, counters                bool
	}{
		{"blackhole", time.Second, 3 * time.Second, 2 * time.Second, 1200*time.Millisecond + time.Nanosecond, false, true},
		{"healthy-900ms-plus-evidence", time.Second, 900 * time.Millisecond, 2 * time.Second, 1300 * time.Millisecond, true, true},
		{"custom-policy", 1500 * time.Millisecond, 1200 * time.Millisecond, 2 * time.Second, 1600 * time.Millisecond, true, true},
		{"raw-diagnostic-unchanged", 0, 3 * time.Second, 2 * time.Second, 2 * time.Second, false, true},
		{"parent-deadline-wins", time.Second, 900 * time.Millisecond, 600 * time.Millisecond, 600 * time.Millisecond, false, true},
		{"successful-dial-without-counters", time.Second, 900 * time.Millisecond, 2 * time.Second, 1300 * time.Millisecond, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.parent)
				defer cancel()
				if tc.limit > 0 {
					ctx = context.WithValue(ctx, targetConnectLimitKey{}, tc.limit)
				}
				began := time.Now()
				transfers, routes := 0, 0
				k := kernel{run: func(ctx context.Context, input, name string, args ...string) ([]byte, error) {
					delay := 50 * time.Millisecond
					if name == "ip" {
						delay = 100 * time.Millisecond
					}
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					switch name {
					case "ip":
						routes++
						return json.Marshal([]object{{"dev": entry.Candidate.Pin.WGInterface, "from": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32")}})
					case "wg":
						if args[2] == "latest-handshakes" {
							return []byte(entry.Candidate.RelayPublicKey + " 1"), nil
						}
						transfers++
						count := 100
						if tc.counters {
							count *= transfers
						}
						return fmt.Appendf(nil, "%s %d %d", entry.Candidate.RelayPublicKey, count, count), nil
					default:
						t.Fatalf("unexpected command %s", name)
						return nil, errors.New("unexpected command")
					}
				}}
				proof, err := k.probeTargetWithDial(ctx, entry, target, func(ctx context.Context, _ Entry, _ relaycatalog.Target) (net.Conn, error) {
					select {
					case <-time.After(tc.dialTime):
						a, b := net.Pipe()
						_ = b.Close()
						return a, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
				if (err == nil) != tc.success || time.Since(began) != tc.elapsed {
					t.Fatalf("success=%v err=%v elapsed=%s want=%s", tc.success, err, time.Since(began), tc.elapsed)
				}
				if tc.success && (proof.duration != tc.dialTime || transfers != 2 || routes != 2 || proof.rx == 0 || proof.tx == 0) {
					t.Fatal("surrounding evidence omitted", proof, transfers, routes)
				}
			})
		})
	}
}
