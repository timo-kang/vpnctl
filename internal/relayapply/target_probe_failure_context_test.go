// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

// Keep real fixture setup outside the virtual clock. Only fake route/counter
// reads and the fake dial run inside it; host scheduling cannot expire the dial.
func TestTargetProbeFailureCapturesDialContextBeforeCleanup(t *testing.T) {
	e, _, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal(err)
	}
	entry := e.journal.Entries[0]
	target := entry.Candidate.Targets[0]
	for _, tc := range []struct {
		name, cause, contextState string
		wait, returnDeadline      bool
	}{
		{name: "refused_while_active", cause: "refused", contextState: "active"},
		{name: "refused_after_deadline", cause: "refused", contextState: "deadline_exceeded", wait: true},
		{name: "deadline_error", cause: "timeout", contextState: "deadline_exceeded", wait: true, returnDeadline: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				ctx := context.WithValue(parent, targetConnectLimitKey{}, time.Millisecond)
				routes, counters, dials := 0, 0, 0
				k := kernel{
					targetLookup: func(context.Context, Entry, relaycatalog.Target) error { routes++; return nil },
					run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
						if input != "" || name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != entry.Candidate.Pin.WGInterface {
							t.Fatal("unexpected command")
						}
						counters++
						switch args[2] {
						case "latest-handshakes":
							return []byte(entry.Candidate.RelayPublicKey + " 1"), nil
						case "transfer":
							return []byte(entry.Candidate.RelayPublicKey + " 100 100"), nil
						default:
							t.Fatal("unexpected counter field")
							return nil, errors.New("unexpected counter field")
						}
					},
				}
				var dialContext context.Context
				proof, err := k.probeTargetWithDial(ctx, entry, target, func(dialCtx context.Context, _ Entry, _ relaycatalog.Target) (net.Conn, error) {
					dials++
					dialContext = dialCtx
					if tc.wait {
						<-dialCtx.Done()
					}
					if tc.returnDeadline {
						return nil, dialCtx.Err()
					}
					return nil, syscall.ECONNREFUSED
				})
				var failure *targetProbeError
				var connect *targetConnectError
				want := relayobserve.ProbeFailure{Stage: "connect", Cause: tc.cause, ContextState: tc.contextState}
				if proof != (targetProof{}) || !errors.As(err, &failure) || failure.failure != want || !errors.As(err, &connect) || connect.reason != tc.cause {
					t.Fatal("dial failure lost its original classification or failure-time context")
				}
				if parent.Err() != nil {
					t.Fatal("dial cleanup or deadline canceled the surrounding proof")
				}
				// Capture precedes cleanup: an active failure is not relabeled
				// canceled, although its dial context is canceled on return.
				wantErr := context.Canceled
				if tc.wait {
					wantErr = context.DeadlineExceeded
				}
				if dialContext == nil || !errors.Is(dialContext.Err(), wantErr) || routes != 1 || counters != 2 || dials != 1 {
					t.Fatal("failed dial retained its context or continued evidence checks")
				}
			})
		})
	}
}
