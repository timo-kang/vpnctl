// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayselect

import "testing"

func TestObservationPolicyPreservesAutomaticCandidatesAndCostBoundary(t *testing.T) {
	for _, mode := range []string{"auto", "manual"} {
		for _, limit := range []int{-1, 0, 10} {
			p := DefaultPolicy()
			p.Mode, p.MaxCost = mode, limit
			if mode == "manual" {
				p.ManualPin = "pin"
			}
			s, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"pin", "other"} {
				for _, cost := range []int{0, 10, 11} {
					want := ""
					if mode == "manual" && path != "pin" {
						want = "manual_pin"
					} else if limit >= 0 && cost > limit {
						want = "cost_limit"
					}
					if got := s.ObservationExclusion(path, cost); got != want {
						t.Fatalf("%s limit=%d path=%s cost=%d: %q want %q", mode, limit, path, cost, got, want)
					}
				}
			}
		}
	}
}
