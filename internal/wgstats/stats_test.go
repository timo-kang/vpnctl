package wgstats

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func sample(at time.Time, n uint64) Sample {
	return Sample{ObservedAt: at, Generation: ID(), Validity: "observed", RX: ptr(Counter(n)), TX: ptr(Counter(n)), Handshake: ptr(at.Add(-time.Second)), Endpoint: true}
}
func TestCounterPrecisionAndInvalidJSON(t *testing.T) {
	for _, n := range []uint64{0, 1, 1<<53 + 1, math.MaxUint64} {
		b, e := json.Marshal(Counter(n))
		if e != nil {
			t.Fatal(e)
		}
		var got Counter
		if e = json.Unmarshal(b, &got); e != nil || uint64(got) != n {
			t.Fatal(string(b), got, e)
		}
	}
	for _, raw := range []string{`0`, `""`, `"01"`, `"-1"`, `"1.0"`, `null`, `"18446744073709551616"`} {
		var n Counter
		if json.Unmarshal([]byte(raw), &n) == nil {
			t.Fatal(raw)
		}
	}
}
func TestCounterBoundaries(t *testing.T) {
	at := time.Now().UTC()
	old := sample(at, 1<<53+1)
	cur := old.Clone()
	cur.ObservedAt = at.Add(time.Second)
	cur.RX = ptr(Counter(1<<53 + 4))
	cur.TX = ptr(Counter(1<<53 + 5))
	v := Compare(cur, &old)
	if v.RXDelta == nil || *v.RXDelta != 3 || *v.TXPerSecond != 4 || v.RateValidity != "inferred" {
		t.Fatal(v)
	}
	cases := []struct {
		name, reason string
		change       func(*Sample)
	}{
		{"reset", "counter_reset", func(s *Sample) { s.RX = ptr(Counter(0)) }},
		{"same", "clock_regressed", func(s *Sample) { s.ObservedAt = at }},
		{"reverse", "clock_regressed", func(s *Sample) { s.ObservedAt = at.Add(-time.Second) }},
		{"gap", "collection_gap", func(s *Sample) { s.ObservedAt = at.Add(MaxGap + time.Nanosecond) }},
		{"generation", "generation_changed", func(s *Sample) { s.Generation = ID() }},
		{"skew", "clock_skew", func(s *Sample) { s.Handshake = ptr(at.Add(time.Hour)) }},
		{"handshake-reset", "handshake_regressed", func(s *Sample) { s.Handshake = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cur.Clone()
			tc.change(&s)
			v := Compare(s, &old)
			if v.RXPerSecond != nil || v.RXDelta != nil || v.RateReason != tc.reason {
				t.Fatal(v)
			}
		})
	}
	v = Compare(cur, nil)
	if v.RateReason != "first_sample" || v.RXPerSecond != nil {
		t.Fatal(v)
	}
	never := sample(at, 0)
	never.Handshake = nil
	v = Compare(never, nil)
	if v.HandshakeState != "never" || v.HandshakeAgeSeconds != nil || *v.RX != 0 {
		t.Fatal(v)
	}
	v = Compare(cur, &old).Fresh(cur.ObservedAt.Add(MaxGap), MaxGap)
	if !v.Stale || v.RXPerSecond != nil || v.HandshakeAgeSeconds != nil || v.RX == nil {
		t.Fatal(v)
	}
	unknown := Unknown(at, "file_source")
	v = Compare(unknown, nil)
	if v.RX != nil || v.HandshakeState != "unknown" || unknown.Validate() != nil {
		t.Fatal(v)
	}
}
