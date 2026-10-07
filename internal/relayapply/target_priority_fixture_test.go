// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Replay the ownership tuples from the manager-install-8 failure: the foreign
// fixture rule occupied the application's priority, despite a different target.
// Moving the fixture outside the reservation range must not weaken the real
// collision rejection or remove the foreign rule during owned route cleanup.
func TestTargetQuarantinePreservesForeignRuleAtFixtureBoundary(t *testing.T) {
	for _, priority := range []uint32{32000, 32761} {
		t.Run(decimal(priority), func(t *testing.T) {
			g := TargetGuard{Table: 841095, Priority: 32000, Metric: 206523584, Prefixes: []string{"198.18.0.2/32"}, Active: &TargetRoute{Interface: "vrb49baa45a26c", Source: "10.78.0.1"}}
			guard := object{"type": "7", "dst": "default", "table": "841095", "protocol": "186", "metric": uint32(206523584), "flags": []any{}}
			foreign := object{"priority": priority, "src": "all", "dst": "203.0.114.0", "dstlen": uint32(24), "table": "65001"}
			m := &targetMachine{
				routes: []object{guard},
				rules:  []object{{"priority": uint32(32000), "src": "all", "dst": "198.18.0.2", "fwmark": "0", "iif": "lo", "table": "841095", "protocol": "186"}, foreign},
			}
			// Populate the fake's canonical deletion tuple for the same route;
			// the real ip JSON represents /32 and numeric enums differently.
			if _, err := m.run(context.Background(), "", "ip", applicationRouteArgs(g, *g.Active, g.Prefixes[0], "add")...); err != nil {
				t.Fatal(err)
			}
			m.mutations = 0
			beforeRules := append([]object(nil), m.rules...)
			k := targetKernel{kernel{run: m.run}}
			err := k.SetRoutes(context.Background(), g, nil, nil)
			if priority == g.Priority {
				if !errors.Is(err, ErrConflict) || m.mutations != 0 || len(m.routes) != 2 {
					t.Fatal("foreign priority collision was repaired or ignored", err, m.mutations)
				}
			} else if err != nil || m.mutations != 1 || len(m.routes) != 1 || !reflect.DeepEqual(m.routes[0], guard) {
				t.Fatal("unrelated fixture priority blocked owned route quarantine", err, m.mutations)
			}
			if !reflect.DeepEqual(beforeRules, m.rules) {
				t.Fatal("owned cleanup changed foreign or guard rules")
			}
		})
	}
}
