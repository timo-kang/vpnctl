// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"
	"time"
)

func TestMeasurementEnvelopeValidation(t *testing.T) {
	now := time.Now().UTC()
	value := 12.5
	m := Measurement{Envelope: Envelope{NodeID: "robot", Target: "server", Timestamp: now, Source: "agent", Unit: "ms", Validity: "observed"}, RTTMs: &value}
	if err := m.Validate(now); err != nil {
		t.Fatal(err)
	}
	m.Validity = "unknown"
	m.Timestamp = now.Add(-8 * 24 * time.Hour)
	if err := m.Validate(now); err == nil {
		t.Fatal("expired measurement accepted")
	}
}
