// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"
)

func encodedAggregate(t *testing.T, a *ProbeAggregate) []byte {
	t.Helper()
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAggregateMatchesRawQueryAcrossPartitionsAndOrder(t *testing.T) {
	s, now := newStore(t)
	rng := rand.New(rand.NewPCG(17, 71))
	var samples []Observation
	// A skewed population catches averaging subgroup p95s, success-only loss
	// denominators, zero-as-missing, and weighting each distinct RTT only once.
	for i := 0; i < 997; i++ {
		ms := 0.0
		if i%10 == 0 {
			ms = float64(1+rng.IntN(60_000_000)) / 1000
		}
		o := obs(fmt.Sprint(i), now.Add(-time.Duration(i+1)*time.Second), &ms)
		if i%7 == 0 {
			o.Success, o.RTTMs = nil, nil
			o.Validity, o.Reason = "unknown", "collector_unavailable"
		} else if i%9 == 0 {
			o.Success, o.RTTMs = pointer(false), nil
		}
		samples = append(samples, o)
	}
	rng.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	var aggregate ProbeAggregate
	for offset := 0; offset < len(samples); offset += 53 {
		end := min(offset+53, len(samples))
		batch := samples[offset:end]
		ingest(t, s, "robot", batch, now)
		ingest(t, s, "robot", batch, now) // storage owns deduplication before rollup
		var part ProbeAggregate
		for _, o := range batch {
			if err := part.Add(o.Success, o.RTTMs); err != nil {
				t.Fatal(err)
			}
		}
		decoded, err := DecodeProbeAggregate(encodedAggregate(t, &part))
		if err != nil {
			t.Fatal(err)
		}
		if err = aggregate.Merge(decoded); err != nil {
			t.Fatal(err)
		}
	}
	buckets, err := s.Query(context.Background(), "robot", now, time.Hour, time.Hour)
	if err != nil || len(buckets) != 1 {
		t.Fatal(buckets, err)
	}
	want := buckets[0]
	got := aggregate.Bucket(want.Stream, want.Time)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregate=%+v raw=%+v", got, want)
	}
	// Permutation does not change encoded bytes, enabling reproducible evidence.
	var reverse ProbeAggregate
	for i := len(samples) - 1; i >= 0; i-- {
		if err := reverse.Add(samples[i].Success, samples[i].RTTMs); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(encodedAggregate(t, &aggregate), encodedAggregate(t, &reverse)) {
		t.Fatal("aggregation depends on arrival order")
	}
}

func TestAggregateUnknownEmptyAndAtomicFailure(t *testing.T) {
	var a ProbeAggregate
	for i := 0; i < 3; i++ {
		if err := a.Add(nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	b := a.Bucket(Stream{}, time.Time{})
	if b.Count != 0 || b.UnknownCount != 3 || b.AvgRTTMs != nil || b.P95RTTMs != nil || b.AvailabilityPct != nil || b.LossPct != nil {
		t.Fatal("unknown interpreted as a completed probe", b)
	}
	before := encodedAggregate(t, &a)
	for _, input := range []struct {
		success *bool
		rtt     *float64
	}{{nil, pointer(0.)}, {pointer(false), pointer(0.)}, {pointer(true), nil}, {pointer(true), pointer(math.NaN())}, {pointer(true), pointer(math.Inf(1))}, {pointer(true), pointer(-1.)}, {pointer(true), pointer(60001.)}} {
		if err := a.Add(input.success, input.rtt); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid RTT accepted", err)
		}
		if !bytes.Equal(before, encodedAggregate(t, &a)) {
			t.Fatal("failed Add changed population")
		}
	}
	if err := a.Merge(&a); !errors.Is(err, ErrInvalid) || !bytes.Equal(before, encodedAggregate(t, &a)) {
		t.Fatal("self merge accepted or modified population", err)
	}
	var empty ProbeAggregate
	decoded, err := DecodeProbeAggregate(encodedAggregate(t, &empty))
	if err != nil || !reflect.DeepEqual(decoded.Bucket(Stream{}, time.Time{}), empty.Bucket(Stream{}, time.Time{})) {
		t.Fatal("empty/gap changed on decode", err)
	}
}

func TestAggregateBudgetsAreAtomicAndRecoverable(t *testing.T) {
	var a ProbeAggregate
	for i := 0; i < MaxAggregateRTTValues; i++ {
		if err := a.Add(pointer(true), pointer(float64(i)/1000)); err != nil {
			t.Fatal(err)
		}
	}
	before := encodedAggregate(t, &a)
	if err := a.Add(pointer(true), pointer(float64(MaxAggregateRTTValues)/1000)); !errors.Is(err, ErrCapacity) || !bytes.Equal(before, encodedAggregate(t, &a)) {
		t.Fatal("distinct limit is not atomic", err)
	}
	var extra ProbeAggregate
	extra.Add(pointer(true), pointer(60_000.))
	if err := a.Merge(&extra); !errors.Is(err, ErrCapacity) || !bytes.Equal(before, encodedAggregate(t, &a)) {
		t.Fatal("merge limit is not atomic", err)
	}
	// Existing values can still be accumulated at the distinct-value ceiling.
	if err := a.Add(pointer(true), pointer(0.)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProbeAggregate(encodedAggregate(t, &a)); err != nil {
		t.Fatal(err)
	}
	// Reach the sample ceiling with a logarithmic number of merges.
	var full ProbeAggregate
	full.Add(pointer(false), nil)
	for full.attempts*2 <= MaxAggregateSamples {
		copy, err := DecodeProbeAggregate(encodedAggregate(t, &full))
		if err != nil || full.Merge(copy) != nil {
			t.Fatal(err)
		}
	}
	remainder := &ProbeAggregate{unknown: MaxAggregateSamples - full.attempts}
	if err := full.Merge(remainder); err != nil {
		t.Fatal(err)
	}
	before = encodedAggregate(t, &full)
	if err := full.Add(nil, nil); !errors.Is(err, ErrCapacity) || !bytes.Equal(before, encodedAggregate(t, &full)) {
		t.Fatal("sample limit is not atomic", err)
	}
}

func TestAggregateRejectsCorruptionAndInvalidEncoding(t *testing.T) {
	var a ProbeAggregate
	a.Add(pointer(true), pointer(0.))
	a.Add(pointer(true), pointer(60_000.))
	a.Add(nil, nil)
	valid := encodedAggregate(t, &a)
	for i := range valid {
		bad := append([]byte(nil), valid...)
		bad[i] ^= 0x80
		if _, err := DecodeProbeAggregate(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("corruption at %d accepted: %v", i, err)
		}
	}
	for i := 0; i < len(valid); i++ {
		if _, err := DecodeProbeAggregate(valid[:i]); !errors.Is(err, ErrInvalid) {
			t.Fatal("truncation accepted", i, err)
		}
	}
	for _, numbers := range [][]uint64{
		{MaxAggregateSamples + 1, 0, 0}, {MaxAggregateSamples, 1, 0}, {1, 0, MaxAggregateRTTValues + 1},
		{1, 0, 1, 60_000_001, 1}, {1, 0, 1, 0, 0}, {1, 0, 1, 0, 2},
		{2, 0, 2, 0, 1, 0, 1}, // duplicate zero RTT key
		{1, 0, 0, 1},          // trailing bytes
	} {
		data := []byte{'V', 'P', 'A', 1}
		for _, n := range numbers {
			data = binary.AppendUvarint(data, n)
		}
		data = binary.LittleEndian.AppendUint32(data, crc32.ChecksumIEEE(data))
		if _, err := DecodeProbeAggregate(data); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid structure accepted", numbers, err)
		}
	}
	if _, err := DecodeProbeAggregate(make([]byte, MaxAggregateBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized encoding accepted", err)
	}
}

func FuzzProbeAggregateDecode(f *testing.F) {
	var a ProbeAggregate
	a.Add(pointer(true), pointer(12.345))
	a.Add(nil, nil)
	encoded, _ := a.MarshalBinary()
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		inputs := [][]byte{data}
		// Also fuzz beyond the checksum gate, so malformed varints/counts are
		// exercised rather than almost every mutation stopping at CRC failure.
		if len(data) >= 8 && len(data) <= MaxAggregateBytes {
			repaired := append([]byte(nil), data...)
			binary.LittleEndian.PutUint32(repaired[len(repaired)-4:], crc32.ChecksumIEEE(repaired[:len(repaired)-4]))
			inputs = append(inputs, repaired)
		}
		for _, input := range inputs {
			a, err := DecodeProbeAggregate(input)
			if err != nil {
				continue
			}
			out := encodedAggregate(t, a)
			if !bytes.Equal(out, input) {
				t.Fatal("accepted noncanonical encoding")
			}
			b := a.Bucket(Stream{}, time.Time{})
			if b.Count < b.Successes || b.Count+b.UnknownCount > MaxAggregateSamples || (b.Count == 0 && b.AvailabilityPct != nil) {
				t.Fatal("invalid population", b)
			}
		}
	})
}
