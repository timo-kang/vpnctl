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
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func TestTargetProbeFailureEvidencePreservesStageAndVerdict(t *testing.T) {
	e, backend, _ := fixture(t, "robot")
	if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
		t.Fatal("could not prepare fake candidate")
	}
	prepared := e.journal.Entries[0]
	target := prepared.Candidate.Targets[0]
	private := "probe-private-sentinel " + prepared.Candidate.RelayPublicKey + " " + prepared.Candidate.InnerAddress + " " + target.ProbeAddress
	unavailable := errors.New(private)
	killed := errors.New("signal: killed: " + private)
	permission := fmt.Errorf("%s: %w", private, syscall.EPERM)
	cancelled := fmt.Errorf("%s: %w", private, context.Canceled)
	deadline := fmt.Errorf("%s: %w", private, context.DeadlineExceeded)
	for _, tc := range []struct {
		name, stage, cause, contextState string
		failure                          error
		invalid                          string
		state, reason                    string
		postcheckReject, noProbe         bool
		stalledTransfer                  bool
	}{
		{name: "route_before", stage: "route_before", cause: "unavailable", failure: unavailable},
		{name: "counters_before", stage: "counters_before", cause: "unavailable", failure: unavailable},
		{name: "connect_unknown", stage: "connect", cause: "unavailable", failure: unavailable},
		{name: "route_after", stage: "route_after", cause: "unavailable", failure: unavailable},
		{name: "counters_after", stage: "counters_after", cause: "unavailable", failure: unavailable},
		{name: "route_permission", stage: "route_before", cause: "permission_denied", failure: permission},
		{name: "counter_permission", stage: "counters_after", cause: "permission_denied", failure: permission},
		{name: "connect_permission", stage: "connect", cause: "permission_denied", failure: permission},
		{name: "returned_canceled_with_active_context", stage: "route_before", cause: "canceled", failure: cancelled},
		{name: "returned_deadline_with_active_context", stage: "counters_before", cause: "deadline_exceeded", failure: deadline},
		{name: "killed_with_active_context", stage: "counters_before", cause: "unavailable", failure: killed},
		{name: "killed_with_canceled_context", stage: "counters_before", cause: "unavailable", contextState: "canceled", failure: killed},
		{name: "killed_with_expired_context", stage: "counters_after", cause: "unavailable", contextState: "deadline_exceeded", failure: killed},
		{name: "counter_shape", stage: "counters_before", cause: "invalid_counters", invalid: "shape"},
		{name: "counter_handshake", stage: "counters_after", cause: "invalid_counters", invalid: "handshake"},
		{name: "counter_rx", stage: "counters_before", cause: "invalid_counters", invalid: "rx"},
		{name: "counter_tx", stage: "counters_after", cause: "invalid_counters", invalid: "tx"},
		{name: "missing_handshake", stage: "transfer", cause: "missing_handshake"},
		{name: "rx_not_advanced", stage: "transfer", cause: "rx_not_advanced"},
		{name: "tx_not_advanced", stage: "transfer", cause: "tx_not_advanced"},
		{name: "handshake_failure_precedes_stalled_counters", stage: "transfer", cause: "missing_handshake", stalledTransfer: true},
		{name: "rx_failure_precedes_tx_failure", stage: "transfer", cause: "rx_not_advanced", stalledTransfer: true},
		{name: "connect_timeout", stage: "connect", cause: "timeout", failure: syscall.ETIMEDOUT, state: "unreachable", reason: "timeout"},
		{name: "connect_refused", stage: "connect", cause: "refused", failure: syscall.ECONNREFUSED, state: "unreachable", reason: "refused"},
		{name: "connect_network_unreachable", stage: "connect", cause: "unreachable", failure: syscall.ENETUNREACH, state: "unreachable", reason: "unreachable"},
		{name: "connect_host_unreachable", stage: "connect", cause: "unreachable", failure: syscall.EHOSTUNREACH, state: "unreachable", reason: "unreachable"},
		{name: "later_postcheck_rejection", stage: "route_after", cause: "unavailable", failure: unavailable, postcheckReject: true, reason: "kernel_changed_during_probe"},
		{name: "successful_probe", state: "reachable", reason: "tcp_connect_verified"},
		{name: "probe_not_executed", noProbe: true, reason: "probe_routing_not_prepared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend.foreign = false
			t.Cleanup(func() { backend.foreign = false })
			entry := prepared
			if tc.noProbe {
				entry.ProbeRouting = false
			}
			wantState, wantReason, wantContext := tc.state, tc.reason, tc.contextState
			if wantState == "" {
				wantState = "unknown"
			}
			if wantReason == "" {
				wantReason = "probe_evidence_unavailable"
			}
			if wantContext == "" {
				wantContext = "active"
			}
			var probeCtx context.Context
			cancelProbe := func() {}
			fault := func() error {
				if tc.contextState == "canceled" {
					cancelProbe()
				}
				if tc.contextState == "deadline_exceeded" {
					<-probeCtx.Done()
				}
				if tc.postcheckReject {
					backend.foreign = true
				}
				return tc.failure
			}
			routes, counterBatch, probes := 0, 0, 0
			k := kernel{
				targetLookup: func(_ context.Context, got Entry, gotTarget relaycatalog.Target) error {
					if got.LinkIndex != entry.LinkIndex || gotTarget.ID != target.ID {
						t.Fatal("probe changed candidate identity")
					}
					routes++
					if routes == 1 && tc.stage == "route_before" || routes == 2 && tc.stage == "route_after" {
						return fault()
					}
					return nil
				},
				run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
					if input != "" || name != "wg" || len(args) != 3 || args[0] != "show" || args[1] != entry.Candidate.Pin.WGInterface {
						t.Fatal("unexpected external command")
					}
					field := args[2]
					if field == "latest-handshakes" {
						counterBatch++
					} else if field != "transfer" {
						t.Fatal("unexpected counter field")
					}
					failingBatch := counterBatch == 1 && tc.stage == "counters_before" || counterBatch == 2 && tc.stage == "counters_after"
					if failingBatch && tc.failure != nil {
						return nil, fault()
					}
					if failingBatch && tc.invalid == "shape" {
						return []byte(private), nil
					}
					if field == "latest-handshakes" {
						value := "1"
						if failingBatch && tc.invalid == "handshake" {
							value = "private-invalid-handshake"
						}
						if counterBatch == 2 && tc.cause == "missing_handshake" {
							value = "0"
						}
						return []byte(entry.Candidate.RelayPublicKey + " " + value), nil
					}
					rx, tx := "100", "100"
					if counterBatch == 2 {
						rx, tx = "200", "200"
						if tc.stalledTransfer {
							rx, tx = "100", "100"
						}
						if tc.cause == "rx_not_advanced" {
							rx = "100"
						}
						if tc.cause == "tx_not_advanced" {
							tx = "100"
						}
					}
					if failingBatch && tc.invalid == "rx" {
						rx = "-1"
					}
					if failingBatch && tc.invalid == "tx" {
						tx = "private-invalid-tx"
					}
					return []byte(entry.Candidate.RelayPublicKey + " " + rx + " " + tx), nil
				},
			}
			var actualProbeErr error
			probe := func(ctx context.Context, got Entry, gotTarget relaycatalog.Target) (targetProof, error) {
				probes++
				probeCtx = ctx
				if tc.contextState == "canceled" {
					probeCtx, cancelProbe = context.WithCancel(ctx)
				} else if tc.contextState == "deadline_exceeded" {
					probeCtx, cancelProbe = context.WithTimeout(ctx, time.Millisecond)
				}
				defer cancelProbe()
				proof, err := k.probeTargetWithDial(probeCtx, got, gotTarget, func(_ context.Context, _ Entry, _ relaycatalog.Target) (net.Conn, error) {
					if tc.stage == "connect" {
						return nil, fault()
					}
					a, b := net.Pipe()
					_ = b.Close()
					return a, nil
				})
				actualProbeErr = err
				return proof, err
			}
			out := e.observePrepared(context.Background(), entry, target, time.Second, TargetObservation{PathID: entry.Candidate.PathID}, probe)
			if out.State != wantState || out.Reason != wantReason {
				t.Fatal("probe diagnostic changed the existing state or reason")
			}
			if tc.noProbe && probes != 0 || !tc.noProbe && probes != 1 {
				t.Fatal("unexpected probe execution count")
			}
			// Existing raw inventory/cancellation/permission errors retain their
			// identity. Known connection failures retain their network verdict.
			if tc.failure != nil && wantState != "unreachable" && !errors.Is(actualProbeErr, tc.failure) {
				t.Fatal("diagnostic wrapping discarded the original error")
			}
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatal("observation JSON failed")
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				t.Fatal("invalid observation JSON")
			}
			diagnostic, present := fields["probe_failure"]
			if tc.stage == "" {
				if present {
					t.Fatal("successful or unexecuted probe emitted failure evidence")
				}
				return
			}
			if !present {
				t.Fatal("missing probe_failure evidence")
			}
			var failure map[string]string
			if json.Unmarshal(diagnostic, &failure) != nil || len(failure) != 3 {
				t.Fatal("probe_failure must contain exactly three string enums")
			}
			if failure["stage"] != tc.stage || failure["cause"] != tc.cause || failure["context_state"] != wantContext {
				t.Fatal("incorrect failure stage, cause, or failure-time context state")
			}
			for _, secret := range []string{"probe-private-sentinel", "private-invalid", entry.Candidate.RelayPublicKey, entry.Candidate.InnerAddress, target.ProbeAddress} {
				if strings.Contains(string(diagnostic), secret) {
					t.Fatal("probe_failure leaked raw error, key, or address")
				}
			}
		})
	}
}
