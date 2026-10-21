// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestServiceTimingValidationAndLegacyJSON(t *testing.T) {
	cfg := fixtureConfig()
	collector := fakeCollector{"lan": {ID: "lan", Interface: "eth0", Kind: "ethernet", Check: Up(), Modem: Up(), GatewayState: Up(), DNS: Up()}}
	p := fakeProber{}
	for _, host := range []string{"relay", "target", "control"} {
		p[host] = probeResult{Route{Check: Up(), Interface: "wg0"}, Check{State: "up", RTTMs: ptr(1.0)}}
	}
	s := (Observer{cfg, collector, p}).Collect(context.Background())
	now := s.At
	for _, tc := range []struct {
		name       string
		start, end *time.Time
		valid      bool
	}{
		{"legacy", nil, nil, true},
		{"instant", &now, &now, true},
		{"interval", ptr(now.Add(-time.Second)), &now, true},
		{"missing-start", nil, &now, false},
		{"missing-end", &now, nil, false},
		{"zero-start", ptr(time.Time{}), &now, false},
		{"zero-end", &now, ptr(time.Time{}), false},
		{"reversed-nanosecond", &now, ptr(now.Add(-time.Nanosecond)), false},
		{"after-cycle-nanosecond", &now, ptr(now.Add(time.Nanosecond)), false},
		{"too-old-start", ptr(now.Add(-7 * 24 * time.Hour)), &now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.Targets[0].ServiceStartedAt, s.Targets[0].ServiceCompletedAt = tc.start, tc.end
			if err := s.Validate(now); (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]any
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			target := wire["targets"].([]any)[0].(map[string]any)
			if _, present := target["service_started_at"]; present != (tc.start != nil) {
				t.Fatal("legacy wire changed")
			}
			var roundtrip Snapshot
			if err := json.Unmarshal(data, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if err := roundtrip.Validate(now); err != nil {
				t.Fatal(err)
			}
		})
	}
}
