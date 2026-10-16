// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/relayobserve"
)

// Public inventory sharing is bounded by an observation, not by an Engine's
// lifetime. A subsequent independent inspection must observe ownership drift
// immediately, including when the previous observation failed or was canceled.
func TestObservationInventoryCannotHideConflictFromNextInspection(t *testing.T) {
	for _, tc := range []struct{ outcome, drift string }{
		{"reachable", "link_owner"},
		{"reachable", "foreign_route"},
		{"reachable", "foreign_rule"},
		{"refused", "link_owner"},
		{"canceled", "link_owner"},
	} {
		t.Run(tc.outcome+"/"+tc.drift, func(t *testing.T) {
			e, _, _ := fixture(t, "robot")
			t.Cleanup(e.Close)
			if _, err := e.PrepareProbe(context.Background(), "p0", ""); err != nil {
				t.Fatal(err)
			}
			entry := e.journal.Entries[0]
			if entry.LeaseVersion != 0 || !entry.ProbeRouting || entry.ProbeScope != 0 {
				t.Fatal("fixture must use command-only unleased probe state")
			}
			state := observationScopeSnapshot(entry)
			run := observationScopeCommands(entry, &state)
			live := nodeKernel{kernel{run: run}}
			e.backend = live
			if before, err := e.Inspect(context.Background()); err != nil || !before.KernelReady {
				t.Fatal("baseline kernel inventory is not valid", before, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			probeCalls := 0
			e.probe = func(context.Context, Entry, relaycatalog.Target) (targetProof, error) {
				probeCalls++
				switch tc.outcome {
				case "refused":
					return targetProof{}, classifyTargetConnect(syscall.ECONNREFUSED)
				case "canceled":
					cancel()
					return targetProof{}, context.Canceled
				default:
					return targetProof{handshake: 1, rx: 1, tx: 1}, nil
				}
			}
			report, err := e.ObserveTarget(ctx, "app", "", time.Second)
			if probeCalls != 1 || len(report.Paths) != 8 {
				t.Fatalf("real observation did not reach the candidate proof: calls=%d report=%+v err=%v", probeCalls, report, err)
			}
			if tc.outcome == "canceled" {
				if !errors.Is(err, context.Canceled) || report.Valid {
					t.Fatal("cancellation fixture was not exercised", err)
				}
			} else {
				want := "reachable"
				if tc.outcome == "refused" {
					want = "unreachable"
				}
				if err != nil || !report.Valid || report.Paths[0].State != want {
					t.Fatal("observation fixture was not exercised", report.Paths[0], err)
				}
			}
			switch tc.drift {
			case "link_owner":
				state.links[0]["ifalias"] = "foreign-owner"
			case "foreign_route":
				state.routes = append(state.routes, object{"dst": "203.0.113.0/24", "table": decimal(entry.Candidate.Pin.Table), "protocol": "4"})
			case "foreign_rule":
				state.rules[1]["protocol"] = "4"
			}
			// This independent live checker is a control: it proves the fake
			// command responses express actual ownership conflicts, not merely
			// an unexpected-but-allowed change in JSON fixture data.
			if ready, err := live.kernel.Check(context.Background(), entry, false); ready || !errors.Is(err, ErrConflict) {
				t.Fatalf("live kernel control missed injected drift: ready=%t err=%v", ready, err)
			}
			after, err := e.Inspect(context.Background())
			if !errors.Is(err, ErrConflict) || after.KernelReady || len(after.Paths) != 1 || after.Paths[0].KernelReady || after.Paths[0].Reason != "kernel_conflict_or_unavailable" {
				t.Fatalf("completed %s observation hid new %s conflict from independent inspection: ready=%t paths=%+v err=%v", tc.outcome, tc.drift, after.KernelReady, after.Paths, err)
			}
		})
	}
}

func observationScopeSnapshot(entry Entry) snapshot {
	p := entry.Candidate.Pin
	s := snapshot{
		links: []object{{"ifname": p.WGInterface, "ifindex": float64(entry.LinkIndex), "group": decimal(entry.Metric), "ifalias": entry.Alias, "linkinfo": map[string]any{"info_kind": "wireguard"}, "flags": []any{"UP"}, "mtu": float64(1280)}},
		routes: []object{
			{"type": "7", "dst": "default", "table": decimal(p.Table), "protocol": "186", "metric": float64(entry.Metric), "flags": []any{}},
			{"dst": strings.TrimSuffix(p.EndpointPrefix, "/32"), "dev": p.Interface, "prefsrc": p.Source, "table": decimal(p.Table), "protocol": "186", "metric": float64(entry.Metric), "flags": []any{}},
		},
		rules: []object{
			{"priority": float64(0), "src": "all", "table": "255"},
			{"priority": float64(p.RulePriority), "src": "all", "fwmark": hexMark(p.FWMark), "table": decimal(p.Table), "protocol": "186"},
			{"priority": float64(32766), "src": "all", "table": "254"},
			{"priority": decimal(probePriority(entry)), "src": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32"), "table": decimal(p.Table), "protocol": "186"},
		},
	}
	for _, prefix := range prefixes(entry) {
		s.routes = append(s.routes, object{"dst": prefix, "dev": p.WGInterface, "prefsrc": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32"), "table": decimal(p.Table), "protocol": "186", "metric": decimal(entry.Metric), "scope": "link"})
	}
	return s
}

func observationScopeCommands(entry Entry, state *snapshot) commandFunc {
	return func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		if input != "" {
			return nil, errors.New("fixture refuses command input or mutations")
		}
		joined := strings.Join(args, " ")
		var out any
		switch {
		case name == "ip" && joined == "-j -N -d link show":
			out = state.links
		case name == "ip" && joined == "-j -N -4 route show table all":
			out = state.routes
		case name == "ip" && joined == "-j -N -4 rule show":
			out = state.rules
		case name == "wg" && joined == "show all fwmark":
			return []byte(entry.Candidate.Pin.WGInterface + " " + decimal(entry.Candidate.Pin.FWMark)), nil
		case name == "ip" && joined == "-j address show dev "+entry.Candidate.Pin.WGInterface:
			out = []object{{"addr_info": []object{{"family": "inet", "local": strings.TrimSuffix(entry.Candidate.InnerAddress, "/32"), "prefixlen": 32}}}}
		case name == "wg" && joined == "show "+entry.Candidate.Pin.WGInterface+" dump":
			return []byte(nodeWireFixture(entry)), nil
		default:
			return nil, fmt.Errorf("unexpected command in isolated fixture: %s %s", name, joined)
		}
		return json.Marshal(out)
	}
}

// The reacquired Engine has a separate cache scope from the closed source.
// Exercise its actual coordinator branch while ensuring the command-only
// kernel rejects each postcheck before it could touch any real lease gate.
func TestObservationInventoryRestoresReacquiredEngineAfterRejectedPostcheck(t *testing.T) {
	e, machine, leases, dir := appFixture(t)
	current := e
	t.Cleanup(func() { current.Close(); current.cache.Close() })
	entry := e.journal.Entries[0]
	state := observationScopeSnapshot(entry)
	state.rules[3]["oif"] = entry.Candidate.Pin.WGInterface
	base := observationScopeCommands(entry, &state)
	invalidWire := true
	wireReads := 0
	rpFilters := map[string]bool{"/proc/sys/net/ipv4/conf/all/rp_filter": true}
	for _, prepared := range e.journal.Entries {
		rpFilters["/proc/sys/net/ipv4/conf/"+prepared.Candidate.Pin.WGInterface+"/rp_filter"] = true
	}
	run := func(ctx context.Context, input, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if input == "" && name == "cat" && len(args) == 1 && rpFilters[args[0]] {
			return []byte("0\n"), nil
		}
		if input == "" && name == "wg" && joined == "show "+entry.Candidate.Pin.WGInterface+" dump" {
			wireReads++
			if invalidWire {
				return []byte("invalid-wireguard-state\n"), nil
			}
		}
		return base(ctx, input, name, args...)
	}
	owner := &testObservationOwner{dir: dir, source: e, machine: machine, kernel: leases,
		edit: func(fresh *Engine) { fresh.backend = nodeKernel{kernel{run: run}} }}
	ctx := relayobserve.WithUnderlayEvents(context.Background(), &testUnderlayEvents{})
	report, fresh, err := e.observeTargetFilteredWithOwnership(ctx, "app", "", time.Second, e.candidateProbe(), nil, owner)
	if fresh != nil {
		current = fresh
	}
	if err != nil || fresh == nil || fresh == e || !e.closed || owner.released != 1 || owner.reacquired != 1 || !report.Valid || len(report.Paths) != 8 || wireReads != 1 {
		t.Fatalf("fresh ownership did not execute the real postcheck: fresh=%t wireReads=%d valid=%t err=%v", fresh != nil && fresh != e, wireReads, report.Valid, err)
	}
	for _, observed := range report.Paths[:3] {
		if observed.State != "unknown" || observed.Reason != "kernel_changed_during_probe" {
			t.Fatalf("postcheck escaped command-only rejection before lease access: %+v", observed)
		}
	}
	invalidWire = false
	state.links[0]["ifalias"] = "foreign-owner-after-handoff"
	if ready, err := (kernel{run: run}).Check(context.Background(), entry, false); ready || !errors.Is(err, ErrConflict) {
		t.Fatalf("live kernel control missed the new conflict: ready=%t err=%v", ready, err)
	}
	// Use the exact live kernel check used by approvedTargetEntry, without
	// invoking nodeKernel's real nft/BPF lease accessor in this local fixture.
	ready, err := fresh.backend.(nodeKernel).kernel.Check(context.Background(), entry, false)
	if ready || !errors.Is(err, ErrConflict) {
		t.Fatalf("reacquired Engine retained postcheck inventory after observation returned: ready=%t err=%v", ready, err)
	}
}
