// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
)

type targetMachine struct {
	routes, rules     []object
	mutations, failAt int
	mode              string
}

func (m *targetMachine) run(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
	if name == "wg" {
		return nil, nil
	}
	key := strings.Join(args, " ")
	switch key {
	case "-j -N -d link show":
		return []byte("[]"), nil
	case "-j -N -4 route show table all":
		return json.Marshal(m.routes)
	case "-j -N -4 rule show":
		return json.Marshal(m.rules)
	}
	if len(args) < 3 || args[0] != "-4" {
		return nil, errors.New("unexpected command")
	}
	m.mutations++
	fault := m.failAt == m.mutations
	if fault && m.mode == "before" {
		return nil, errors.New("injected before command")
	}
	values := map[string]string{}
	for i := 3; i+1 < len(args); i++ {
		values[args[i]] = args[i+1]
	}
	number := func(s string) uint32 { n, _ := num(values[s]); return n }
	var o object
	var rows *[]object
	switch args[1] {
	case "route":
		o = object{"type": "unreachable", "dst": "default", "table": number("table"), "protocol": number("proto"), "metric": number("metric")}
		if args[3] != "unreachable" {
			o = object{"dst": args[3], "table": number("table"), "protocol": number("proto"), "metric": number("metric"), "dev": values["dev"], "prefsrc": values["src"], "scope": values["scope"]}
		}
		rows = &m.routes
	case "rule":
		o = object{"priority": number("priority"), "src": "all", "dst": values["to"], "iif": values["iif"], "fwmark": uint32(0), "table": number("lookup"), "protocol": number("protocol")}
		rows = &m.rules
	default:
		return nil, errors.New("unexpected mutation")
	}
	index := slices.IndexFunc(*rows, func(r object) bool { return reflect.DeepEqual(r, o) })
	if args[2] == "add" {
		if args[1] == "route" {
			for _, row := range *rows {
				if fmt.Sprint(row["table"]) == fmt.Sprint(o["table"]) && str(row, "dst") == str(o, "dst") && fmt.Sprint(row["metric"]) == fmt.Sprint(o["metric"]) {
					return nil, errors.New("route key exists")
				}
			}
		}
		if index >= 0 {
			return nil, errors.New("exists")
		}
		*rows = append(*rows, o)
	} else if args[2] == "del" {
		if index < 0 {
			return nil, errors.New("absent")
		}
		*rows = append((*rows)[:index], (*rows)[index+1:]...)
	} else {
		return nil, errors.New("unexpected verb")
	}
	if fault {
		if m.mode == "crash" {
			panic("simulated death")
		}
		return nil, errors.New("injected after command")
	}
	return nil, nil
}
func targetFixture(t *testing.T) (*Engine, *targetMachine, string) {
	e, _, dir := fixture(t, "robot")
	m := &targetMachine{routes: []object{}, rules: []object{}}
	e.targets = targetKernel{kernel{run: m.run}}
	return e, m, dir
}
func reopenTarget(t *testing.T, e *Engine, m *targetMachine, dir string) *Engine {
	n := reopen(t, e, dir)
	n.targets = targetKernel{kernel{run: m.run}}
	return n
}
func TestTargetGuardCommandFailureAndRestart(t *testing.T) {
	for _, operation := range []string{"reserve", "release"} {
		for point := 1; point <= 2; point++ {
			for _, mode := range []string{"before", "after", "crash"} {
				t.Run(operation+"/"+decimal(uint32(point))+"/"+mode, func(t *testing.T) {
					e, m, dir := targetFixture(t)
					ctx := context.Background()
					if operation == "release" {
						if _, err := e.ReserveTarget(ctx, "app", ""); err != nil {
							t.Fatal(err)
						}
					}
					m.mutations = 0
					m.failAt = point
					m.mode = mode
					func() {
						defer func() {
							v := recover()
							if mode == "crash" && v == nil {
								t.Error("crash not exercised")
							}
							if mode != "crash" && v != nil {
								panic(v)
							}
						}()
						var err error
						if operation == "reserve" {
							_, err = e.ReserveTarget(ctx, "app", "")
						} else {
							_, err = e.ReleaseTarget(ctx, "app")
						}
						if err == nil {
							t.Error("fault accepted")
						}
					}()
					e = reopenTarget(t, e, m, dir)
					m.failAt = 0
					out, err := e.RecoverTarget(ctx, "app")
					if err != nil {
						t.Fatal(err)
					}
					if out.Activated {
						t.Fatal("reservation activated a path")
					}
					if operation == "reserve" {
						if !out.Guarded || len(m.rules) != 1 || len(m.routes) != 1 {
							t.Fatalf("incomplete recovery: %+v", out)
						}
						for i := 0; i < 3; i++ {
							if _, err = e.ReserveTarget(ctx, "app", ""); err != nil {
								t.Fatal(err)
							}
							if _, err = e.RecoverTarget(ctx, "app"); err != nil {
								t.Fatal(err)
							}
						}
						if len(m.rules) != 1 || len(m.routes) != 1 {
							t.Fatal("duplicate objects")
						}
						if _, err = e.ReleaseTarget(ctx, "app"); err != nil {
							t.Fatal(err)
						}
					}
					if len(m.rules) != 0 || len(m.routes) != 0 || len(e.journal.Targets) != 0 {
						t.Fatal("resources left after release")
					}
				})
			}
		}
	}
}
func TestTargetGuardStorageFailureNeverClaimsSuccess(t *testing.T) {
	for _, operation := range []string{"reserve", "release"} {
		for _, after := range []bool{false, true} {
			for point := 1; point <= 2; point++ {
				t.Run(operation+"/"+decimal(uint32(point))+"/"+map[bool]string{true: "after", false: "before"}[after], func(t *testing.T) {
					e, m, dir := targetFixture(t)
					ctx := context.Background()
					if operation == "release" {
						if _, err := e.ReserveTarget(ctx, "app", ""); err != nil {
							t.Fatal(err)
						}
					}
					save := e.save
					calls := 0
					e.save = func(b []byte) error {
						calls++
						if calls == point {
							if after {
								if err := save(b); err != nil {
									return err
								}
							}
							return errors.New("injected persistence error")
						}
						return save(b)
					}
					var out TargetGuardResult
					var err error
					if operation == "reserve" {
						out, err = e.ReserveTarget(ctx, "app", "")
					} else {
						out, err = e.ReleaseTarget(ctx, "app")
					}
					if err == nil || out.Guarded || out.Activated || !e.uncertain {
						t.Fatal("uncertain save reported success", out, err)
					}
					before := m.mutations
					if _, err = e.RecoverTarget(ctx, "app"); err == nil || before != m.mutations {
						t.Fatal("continued after uncertain persistence")
					}
					e = reopenTarget(t, e, m, dir)
					if e.targetIndex("app") >= 0 {
						if _, err = e.RecoverTarget(ctx, "app"); err != nil {
							t.Fatal(err)
						}
					}
					if operation == "reserve" && point == 1 && !after && m.mutations != 0 {
						t.Fatal("mutated before durable intent")
					}
					if operation == "release" && point == 1 && !after {
						if len(m.rules) != 1 || len(m.routes) != 1 {
							t.Fatal("released before durable intent")
						}
					}
				})
			}
		}
	}
}
func TestTargetGuardDefinitionAndKernelChangesAreNotAdopted(t *testing.T) {
	e, m, dir := targetFixture(t)
	ctx := context.Background()
	if _, err := e.ReserveTarget(ctx, "missing", ""); err == nil {
		t.Fatal("unapproved target")
	}
	if _, err := e.ReserveTarget(ctx, "app", "wrong-controller"); err == nil {
		t.Fatal("wrong controller")
	}
	if m.mutations != 0 {
		t.Fatal("invalid approval mutated kernel")
	}
	out, err := e.ReserveTarget(ctx, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	original := out.Reservation.Metric
	m.routes[0]["metric"] = original + 1
	for _, call := range []func(context.Context, string) (TargetGuardResult, error){e.InspectTarget, e.RecoverTarget, e.ReleaseTarget} {
		before := m.mutations
		if result, err := call(ctx, "app"); err == nil || result.Guarded || result.Activated || m.mutations != before {
			t.Fatal("foreign object adopted or removed")
		}
	}
	e = reopenTarget(t, e, m, dir)
	if _, err = e.RecoverTarget(ctx, "app"); err == nil {
		t.Fatal("restart adopted foreign object")
	}
	m.routes[0]["metric"] = original
	if _, err = e.RecoverTarget(ctx, "app"); err != nil {
		t.Fatal(err)
	}
}
func TestTargetGuardMissingRouteDoesNotRepairBeneathLiveRules(t *testing.T) {
	e, m, dir := targetFixture(t)
	ctx := context.Background()
	if _, err := e.ReserveTarget(ctx, "app", ""); err != nil {
		t.Fatal(err)
	}
	// Persisted pending state with a rule but no guard is not a valid crash prefix.
	e.journal.Targets[0].Phase = "reserving"
	if err := e.persist(); err != nil {
		t.Fatal(err)
	}
	m.routes = []object{}
	e = reopenTarget(t, e, m, dir)
	before := m.mutations
	if _, err := e.RecoverTarget(ctx, "app"); err == nil || m.mutations != before {
		t.Fatal("external deletion silently repaired")
	}
}
func TestTargetGuardJournalValidation(t *testing.T) {
	e, _, _ := targetFixture(t)
	if _, err := e.ReserveTarget(context.Background(), "app", ""); err != nil {
		t.Fatal(err)
	}
	original := e.journal.Targets[0]
	for _, mutate := range []func(*TargetGuard){
		func(g *TargetGuard) { g.AllocationSlot++ },
		func(g *TargetGuard) {
			g.AllocationSlot = maxTargetAllocationSlot + 1
			g.Table, g.Priority = targetAllocatedSlots(*g)
		},
		func(g *TargetGuard) { g.Table++ }, func(g *TargetGuard) { g.Priority++ }, func(g *TargetGuard) { g.Owner = "vpnctl:bad" }, func(g *TargetGuard) { g.Node = "elsewhere" }, func(g *TargetGuard) { g.Phase = "active" }, func(g *TargetGuard) { g.Prefixes = []string{"0.0.0.0/0"} }, func(g *TargetGuard) { g.Prefixes = []string{"198.18.0.2/32", "198.18.0.2/32"} },
	} {
		copy := original
		mutate(&copy)
		if validateTargetGuards([]TargetGuard{copy}, "robot") == nil {
			t.Fatalf("accepted %+v", copy)
		}
	}
	if validateTargetGuards([]TargetGuard{original, original}, "robot") == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestTargetGuardRevocationDoesNotRemoveBlockingIntent(t *testing.T) {
	e, m, dir := targetFixture(t)
	ctx := context.Background()
	m.failAt = 2
	m.mode = "before"
	if _, err := e.ReserveTarget(ctx, "app", ""); err == nil {
		t.Fatal("fault missing")
	}
	// Explicit rejection makes the cache unusable without removing the journal.
	if _, err := e.cache.Refresh(ctx, &rejectTargetApproval{}); err == nil {
		t.Fatal("rejection missing")
	}
	e = reopenTarget(t, e, m, dir)
	m.failAt = 0
	if out, err := e.RecoverTarget(ctx, "app"); err != nil || !out.Guarded {
		t.Fatal(out, err)
	}
	if _, err := e.ReserveTarget(ctx, "app", ""); err == nil {
		t.Fatal("unusable approval accepted")
	}
	if out, err := e.InspectTarget(ctx, "app"); err != nil || !out.Guarded {
		t.Fatal("revocation reopened target", out, err)
	}
}

type rejectTargetApproval struct{}

func (*rejectTargetApproval) RelayCatalog(context.Context, string) (relaycatalog.View, error) {
	return relaycatalog.View{}, &api.HTTPError{StatusCode: 403}
}
func (*rejectTargetApproval) BindRelayPath(context.Context, relaycatalog.BindRequest) (relaycatalog.View, error) {
	return relaycatalog.View{}, &api.HTTPError{StatusCode: 403}
}

func TestTargetGuardConflictsPreserveForeignResources(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(*targetMachine, TargetGuard){
		"occupied_table": func(m *targetMachine, g TargetGuard) {
			m.routes = append(m.routes, object{"table": g.Table, "dst": "default", "type": "unreachable", "protocol": 186, "metric": g.Metric})
		},
		"priority_collision": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": g.Priority, "src": "all", "table": 999})
		},
		"foreign_table_reader": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": 1, "src": "all", "table": g.Table})
		},
		"earlier_unmarked": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": 100, "src": "all", "table": 999})
		},
		"earlier_source_rule": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": 100, "src": "192.0.2.1", "table": 999})
		},
		"earlier_uid_rule": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": 100, "src": "all", "uidrange": "1000-2000", "table": 999})
		},
		"earlier_inverted": func(m *targetMachine, g TargetGuard) {
			m.rules = append(m.rules, object{"priority": 100, "src": "all", "dst": "203.0.113.0/24", "not": true, "table": 999})
		},
		"foreign_target_route": func(m *targetMachine, g TargetGuard) {
			m.routes = append(m.routes, object{"table": 254, "dst": "198.18.0.2", "dev": "foreign0"})
		},
		"local_target_address": func(m *targetMachine, g TargetGuard) {
			m.routes = append(m.routes, object{"table": 255, "dst": "198.18.0.2", "type": "local"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, m, _ := targetFixture(t)
			r, err := e.cache.Status()
			if err != nil {
				t.Fatal(err)
			}
			table, priority := targetSlots(r.ControllerID, r.NodeID, "app")
			edit(m, TargetGuard{Table: table, Priority: priority, Metric: 100000})
			before, _ := json.Marshal([]any{m.routes, m.rules})
			if out, err := e.ReserveTarget(ctx, "app", ""); err == nil || out.Guarded || out.Activated {
				t.Fatal("foreign state accepted", out, err)
			}
			after, _ := json.Marshal([]any{m.routes, m.rules})
			if m.mutations != 0 || string(before) != string(after) || len(e.journal.Targets) != 0 {
				t.Fatal("foreign resources changed")
			}
		})
	}
}
func TestTargetGuardAllowsUnrelatedDefaultsAndCandidateProbes(t *testing.T) {
	e, m, _ := targetFixture(t)
	ctx := context.Background()
	if _, err := e.PrepareProbe(ctx, "p0", ""); err != nil {
		t.Fatal(err)
	}
	candidate := e.journal.Entries[0]
	m.routes = append(m.routes, object{"table": 254, "dst": "default", "gateway": "192.0.2.1"}, object{"table": candidate.Candidate.Pin.Table, "dst": "198.18.0.2", "protocol": 186, "metric": candidate.Metric, "dev": candidate.Candidate.Pin.WGInterface, "prefsrc": strings.TrimSuffix(candidate.Candidate.InnerAddress, "/32")})
	m.rules = append(m.rules, object{"priority": 0, "src": "all", "table": 255}, object{"priority": 100, "src": "all", "dst": "203.0.113.0/24", "table": 999}, object{"priority": 200, "src": "all", "fwmark": 1, "table": 998}, object{"priority": probePriority(candidate), "src": candidate.Candidate.InnerAddress, "table": candidate.Candidate.Pin.Table, "protocol": 186})
	if out, err := e.ReserveTarget(ctx, "app", ""); err != nil || !out.Guarded {
		t.Fatal(out, err)
	}
	if _, err := e.ReleaseTarget(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	if len(m.routes) != 2 || len(m.rules) != 4 {
		t.Fatal("unrelated resources changed")
	}
}

// Exercise every prefix boundary of the largest catalog target. The intent
// represents a previously approved reservation; recovery needs no new grant.
func TestTargetGuardEightPrefixCrashPrefixes(t *testing.T) {
	for point := 1; point <= 9; point++ {
		t.Run(decimal(uint32(point)), func(t *testing.T) {
			e, m, dir := targetFixture(t)
			ctx := context.Background()
			if _, err := e.ReserveTarget(ctx, "app", ""); err != nil {
				t.Fatal(err)
			}
			g := e.journal.Targets[0]
			if _, err := e.ReleaseTarget(ctx, "app"); err != nil {
				t.Fatal(err)
			}
			g.Prefixes = []string{"198.18.0.2/32", "198.18.1.2/32", "198.18.2.2/32", "198.18.3.2/32", "198.18.4.2/32", "198.18.5.2/32", "198.18.6.2/32", "198.18.7.2/32"}
			g.Phase = "reserving"
			e.journal.Targets = []TargetGuard{g}
			if err := e.persist(); err != nil {
				t.Fatal(err)
			}
			m.mutations = 0
			m.failAt = point
			m.mode = "crash"
			func() {
				defer func() {
					if recover() == nil {
						t.Error("crash missing")
					}
				}()
				_, _ = e.RecoverTarget(ctx, "app")
			}()
			e = reopenTarget(t, e, m, dir)
			m.failAt = 0
			if out, err := e.RecoverTarget(ctx, "app"); err != nil || !out.Guarded {
				t.Fatal(out, err)
			}
			if len(m.rules) != 8 || len(m.routes) != 1 {
				t.Fatal("incomplete or duplicate recovery")
			}
			if _, err := e.ReleaseTarget(ctx, "app"); err != nil {
				t.Fatal(err)
			}
			if len(m.rules) != 0 || len(m.routes) != 0 {
				t.Fatal("partial release")
			}
		})
	}
}
