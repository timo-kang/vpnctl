// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"vpnctl/internal/relayplan"
)

// ip -j -N rule emits prefix lengths separately, e.g. the preserved CI row
// {"priority":32000,"src":"all","dst":"203.0.114.0","dstlen":24,"table":"65001"}.
// Pass every case through the real public-inventory JSON decoder. The injected
// runner serves read-only data and cannot execute commands or mutate the host.
func policyPrefixSnapshot(t *testing.T, selector object, priority uint32) snapshot {
	t.Helper()
	rule := object{"priority": priority, "src": "all", "table": "65001"}
	for key, value := range selector {
		rule[key] = value
	}
	raw, err := json.Marshal([]object{rule})
	if err != nil {
		t.Fatal(err)
	}
	k := kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
		if input != "" {
			t.Fatal("inventory attempted a mutation")
		}
		switch name + " " + strings.Join(args, " ") {
		case "ip -j -N -d link show", "ip -j -N -4 route show table all":
			return []byte(`[]`), nil
		case "ip -j -N -4 rule show":
			return raw, nil
		case "wg show all fwmark":
			return nil, nil
		default:
			t.Fatalf("unexpected inventory read or mutation: %s %v", name, args)
			return nil, ErrConflict
		}
	}}
	s, err := k.snapshot(context.Background())
	if err != nil {
		t.Fatal("public inventory decode failed before prefix conflict validation", err)
	}
	return s
}

type policyPrefixCase struct {
	name     string
	selector object
	conflict bool
}

func policyPrefixCases(field, address, network, unrelated, otherHost string, bits int) []policyPrefixCase {
	selector := func(address any, length ...any) object {
		o := object{field: address}
		if len(length) != 0 {
			o[field+"len"] = length[0]
		}
		return o
	}
	cases := []policyPrefixCase{
		{"split-overlapping-prefix", selector(network, bits), true},
		{"split-unrelated-prefix", selector(unrelated, 24), false},
		{"split-default", selector("0.0.0.0", 0), true},
		{"split-default-with-host-bits", selector(unrelated, 0), true},
		{"split-overlap-with-host-bits", selector(otherHost, bits), true},
		{"cidr-overlap-with-host-bits", selector(fmt.Sprintf("%s/%d", otherHost, bits)), true},
		{"split-one-bit-overlap", selector(network, 1), true},
		{"split-matching-host", selector(address, 32), true},
		{"split-different-host", selector(otherHost, 32), false},
		{"implicit-matching-host", selector(address), true},
		{"implicit-different-host", selector(otherHost), false},
		{"cidr-overlapping-prefix", selector(fmt.Sprintf("%s/%d", network, bits)), true},
		{"cidr-unrelated-prefix", selector(unrelated + "/24"), false},
		{"cidr-default", selector("0.0.0.0/0"), true},
		{"cidr-matching-host", selector(address + "/32"), true},
		{"cidr-different-host", selector(otherHost + "/32"), false},
		{"cidr-matching-length", selector(unrelated+"/24", 24), false},
		{"cidr-length-disagrees", selector(unrelated+"/24", 16), true},
		{"missing-selector", object{}, true},
		{"empty-selector", selector(""), true},
		{"default-selector", selector("default"), true},
		{"zero-length-without-address", object{field + "len": 0}, true},
		{"all", selector("all"), true},
		{"all-zero-length", selector("all", 0), true},
		{"all-nonzero-length", selector("all", 24), true},
		{"length-without-address", object{field + "len": 24}, true},
		{"invalid-address", selector("invalid", 24), true},
		{"non-string-address", selector(203, 24), true},
		{"null-address", selector(nil, 24), true},
		{"ipv6-in-ipv4-inventory", selector("2001:db8::", 24), true},
		{"mapped-ipv6-in-ipv4-inventory", selector("::ffff:203.0.113.0/120"), true},
		{"inverted-unrelated-prefix", selector(unrelated, 24), true},
		{"uninverted-unrelated-prefix", selector(unrelated, 24), false},
	}
	cases[len(cases)-2].selector["not"] = true
	cases[len(cases)-1].selector["not"] = false
	// Malformed lengths use a disjoint address: rejection must come from the
	// ambiguous selector itself, not from a coincidental host-address overlap.
	for _, malformed := range []struct {
		name  string
		value any
	}{
		{"negative", -1}, {"above-ipv4-range", 33}, {"integer-overflow", uint64(1) << 32},
		{"fractional", 24.5}, {"string", "24"}, {"null", nil}, {"boolean", true},
		{"array", []int{24}}, {"object", object{"bits": 24}},
	} {
		cases = append(cases, policyPrefixCase{"invalid-length-" + malformed.name, selector(unrelated, malformed.value), true})
	}
	return cases
}

func TestTargetGuardConflictsWithSplitDestinationPrefix(t *testing.T) {
	guard := TargetGuard{
		Table: 841095, Priority: 32010, Metric: 206523584,
		Prefixes: []string{"198.18.0.2/32"},
	}
	for _, tc := range policyPrefixCases("dst", "198.18.0.2", "198.18.0.0", "203.0.114.0", "198.18.0.3", 24) {
		t.Run(tc.name, func(t *testing.T) {
			s := policyPrefixSnapshot(t, tc.selector, 32000)
			_, err := targetGuardConflicts(s, guard, nil, false)
			if tc.conflict && !errors.Is(err, ErrConflict) || !tc.conflict && err != nil {
				t.Fatalf("destination rule conflict=%v; want %v (selector=%v)", err, tc.conflict, tc.selector)
			}
		})
	}
}

func TestCandidateConflictsWithSplitProbeSourcePrefix(t *testing.T) {
	entry := Entry{ProbeRouting: true, Candidate: relayplan.Candidate{
		InnerAddress: "10.78.0.3/32",
		Pin: &relayplan.PinInput{
			WGInterface: "vrprefixprobe", FWMark: 0x76000001,
			Table: 100001, RulePriority: 20000,
		},
	}}
	// Put the foreign rule after transport marking but before the source probe
	// rule, isolating the source-prefix check from earlier-mark conflict checks.
	const foreignPriority = 26000
	if foreignPriority <= entry.Candidate.Pin.RulePriority || foreignPriority >= probePriority(entry) {
		t.Fatal("fixture does not isolate probe-source precedence")
	}
	for _, tc := range policyPrefixCases("src", "10.78.0.3", "10.78.0.0", "192.0.2.0", "10.78.0.4", 16) {
		t.Run(tc.name, func(t *testing.T) {
			s := policyPrefixSnapshot(t, tc.selector, foreignPriority)
			// Missing source is iproute2's usual all-source selector.
			if len(tc.selector) == 0 {
				delete(s.rules[0], "src")
			}
			err := conflicts(s, entry, false)
			if tc.conflict && !errors.Is(err, ErrConflict) || !tc.conflict && err != nil {
				t.Fatalf("source rule conflict=%v; want %v (selector=%v)", err, tc.conflict, tc.selector)
			}
		})
	}
}
