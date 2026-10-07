// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayselect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayobserve"
)

// Replay only the public timestamps and successful proof shape from CPU8 CI
// job 112707371519, healthy position zero. Every independent app2 probe was
// reachable; this isolates freshness continuity from transport, CPU, and I/O.
// This is a diagnostic replay, not a performance simulation or an SLO waiver.
func TestCPU8SuccessfulProbeReplayPreservesFreshnessBoundary(t *testing.T) {
	cycles := []struct {
		started, finished string
		probes            []string
	}{
		{"2026-10-07T08:52:44.061552115Z", "2026-10-07T08:52:47.393874299Z", []string{"2026-10-07T08:52:45.589282529Z", "2026-10-07T08:52:45.728702559Z", "2026-10-07T08:52:45.869196151Z", "2026-10-07T08:52:45.996479006Z", "2026-10-07T08:52:46.116693431Z", "2026-10-07T08:52:46.267599081Z", "2026-10-07T08:52:46.411443259Z", "2026-10-07T08:52:46.543038672Z"}},
		{"2026-10-07T08:52:48.882562856Z", "2026-10-07T08:52:52.07510765Z", []string{"2026-10-07T08:52:50.478913845Z", "2026-10-07T08:52:50.845290381Z", "2026-10-07T08:52:50.607220599Z", "2026-10-07T08:52:50.725505482Z", "2026-10-07T08:52:51.108949193Z", "2026-10-07T08:52:50.978066016Z", "2026-10-07T08:52:51.250201328Z", "2026-10-07T08:52:50.335685666Z"}},
		{"2026-10-07T08:52:59.289757235Z", "2026-10-07T08:53:02.786906026Z", []string{"2026-10-07T08:53:01.044781194Z", "2026-10-07T08:53:01.193602989Z", "2026-10-07T08:53:01.333133516Z", "2026-10-07T08:53:01.617605845Z", "2026-10-07T08:53:01.462580175Z", "2026-10-07T08:53:01.756304451Z", "2026-10-07T08:53:00.905461611Z", "2026-10-07T08:53:01.90507935Z"}},
		{"2026-10-07T08:53:10.005889179Z", "2026-10-07T08:53:13.469361745Z", []string{"2026-10-07T08:53:11.976989582Z", "2026-10-07T08:53:11.685412248Z", "2026-10-07T08:53:11.827837821Z", "2026-10-07T08:53:12.106845724Z", "2026-10-07T08:53:12.426566239Z", "2026-10-07T08:53:12.266539036Z", "2026-10-07T08:53:11.557387138Z", "2026-10-07T08:53:12.588454081Z"}},
	}
	parse := func(raw string) time.Time {
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	for _, saved := range []time.Duration{0, 2 * time.Second} {
		t.Run(fmt.Sprintf("admission_saved_%s", saved), func(t *testing.T) {
			selector, err := New(DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			base := parse(cycles[0].started)
			var now time.Time
			selector.now = func() time.Time { return now }
			selector.boot = func() (time.Duration, error) { return time.Hour + now.Sub(base), nil }
			var last Decision
			for n, cycle := range cycles {
				// The control shortens only inter-cycle delay. It keeps the policy,
				// successful proof shape, and intra-cycle observation positions intact.
				shift := time.Duration(max(0, n-1)) * saved
				now = parse(cycle.finished).Add(-shift)
				report := relayobserve.TargetReport{SchemaVersion: 1, ControllerID: "fixture", NodeID: "robot", Generation: 11, TargetID: "app2", StartedAt: parse(cycle.started).Add(-shift), ObservedAt: now, BootTime: time.Hour + now.Sub(base), ApprovalUntil: base.Add(time.Hour), Valid: true}
				for i, observed := range cycle.probes {
					path := fmt.Sprintf("p%d%d", i/4, i%4)
					report.Paths = append(report.Paths, relayobserve.TargetObservation{PathID: path, RelayID: fmt.Sprintf("r%d", i/4), UnderlayID: fmt.Sprintf("lan%d", i%4), Fingerprint: strings.Repeat(fmt.Sprint(i), 64), State: "reachable", Reason: "tcp_connect_verified", ObservedAt: parse(observed).Add(-shift), ConnectTime: time.Millisecond, Handshake: 1, RXDelta: 96, TXDelta: 192})
				}
				last = selector.Decide(report)
				if n == 1 && last.DesiredPathID != "p00" {
					t.Fatalf("initial independent app failed: %+v", last)
				}
				if last.DesiredPathID != "" {
					selector.RecordApplied(last.DesiredPathID, now)
				}
			}
			if saved == 0 {
				if last.DesiredPathID != "" || last.Reason != "candidate_evidence_incomplete" {
					t.Fatalf("recorded loss was not reproduced: %+v", last)
				}
				for _, c := range last.Candidates {
					if c.State != "reachable" || c.Eligible || c.ConsecutiveSuccesses != 1 || c.Exclusion != "confirming" {
						t.Fatalf("healthy proof did not expose confirmation gap: %+v", c)
					}
				}
			} else if last.DesiredPathID == "" {
				t.Fatalf("reducing inter-cycle delay did not preserve the unchanged freshness gate: %+v", last)
			}
		})
	}
}
