// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"sort"
	"time"
)

// These are budgets for the tiered-retention candidate, not enabled retention
// settings. The current Store still retains raw probes for seven days.
const (
	CandidateRawRetention = 6 * time.Hour
	CandidateRollupWidth  = time.Hour
	MaxAggregateSamples   = 4_000_000 // encoding limit, independent of the raw row quota
	MaxAggregateRTTValues = 65_536
	MaxAggregateBytes     = 1 << 20
)

// ProbeAggregate is a lossless distribution of already validated, distinct
// probes from one stream and one interval. The storage owner must deduplicate
// IDs and ensure disjoint intervals when merging: this deliberately retains no
// IDs, timestamps, reasons or ordering. It cannot reconstruct partial intervals,
// jitter or live quality state, and is not a substitute for a raw observation.
// Its zero value is empty; callers must not copy it after first use or use it
// concurrently. Use the binary representation for detached snapshots.
type ProbeAggregate struct {
	attempts, unknown, successes, sumUS int64
	rtts                                map[int64]int64
}

// Add preserves the same numeric semantics as raw history: unknown is outside
// the attempt denominator; successful zero RTT is a measurement, not missing.
// Any rejected update leaves the aggregate unchanged.
func (a *ProbeAggregate) Add(success *bool, rttMS *float64) error {
	if a.attempts+a.unknown >= MaxAggregateSamples {
		return fmt.Errorf("%w: aggregate sample limit", ErrCapacity)
	}
	var us int64
	if success == nil || !*success {
		if rttMS != nil {
			return fmt.Errorf("%w: non-success carries RTT", ErrInvalid)
		}
	} else {
		if rttMS == nil || math.IsNaN(*rttMS) || math.IsInf(*rttMS, 0) || *rttMS < 0 || *rttMS > 60_000 {
			return fmt.Errorf("%w: invalid aggregate RTT", ErrInvalid)
		}
		us = int64(math.Round(*rttMS * 1000))
		if _, exists := a.rtts[us]; !exists && len(a.rtts) >= MaxAggregateRTTValues {
			return fmt.Errorf("%w: aggregate distinct RTT limit", ErrCapacity)
		}
	}
	if success == nil {
		a.unknown++
		return nil
	}
	a.attempts++
	if *success {
		if a.rtts == nil {
			a.rtts = make(map[int64]int64)
		}
		a.rtts[us]++
		a.successes++
		a.sumUS += us
	}
	return nil
}

// Merge combines disjoint populations, rather than averaging their percentiles.
// Validation happens before mutation so a capacity failure is atomic.
func (a *ProbeAggregate) Merge(b *ProbeAggregate) error {
	if a == b {
		return fmt.Errorf("%w: aggregate cannot merge itself", ErrInvalid)
	}
	if a.attempts+a.unknown+b.attempts+b.unknown > MaxAggregateSamples {
		return fmt.Errorf("%w: aggregate sample limit", ErrCapacity)
	}
	newValues := len(a.rtts)
	for us := range b.rtts {
		if _, exists := a.rtts[us]; !exists {
			newValues++
		}
	}
	if newValues > MaxAggregateRTTValues {
		return fmt.Errorf("%w: aggregate distinct RTT limit", ErrCapacity)
	}
	if len(b.rtts) > 0 && a.rtts == nil {
		a.rtts = make(map[int64]int64, newValues)
	}
	for us, n := range b.rtts {
		a.rtts[us] += n
	}
	a.attempts += b.attempts
	a.unknown += b.unknown
	a.successes += b.successes
	a.sumUS += b.sumUS
	return nil
}

// Bucket produces the raw API's exact average and nearest-rank p95. Its caller
// owns stream identity and interval boundaries; only whole aggregate intervals
// may be included in the population.
func (a *ProbeAggregate) Bucket(stream Stream, start time.Time) Bucket {
	b := Bucket{Stream: stream, Time: start, Count: int(a.attempts), UnknownCount: int(a.unknown), Successes: int(a.successes)}
	if a.attempts > 0 {
		b.AvailabilityPct = pointer(100 * float64(a.successes) / float64(a.attempts))
		b.LossPct = pointer(100 - *b.AvailabilityPct)
	}
	if a.successes > 0 {
		b.AvgRTTMs = pointer(float64(a.sumUS) / float64(a.successes) / 1000)
		rank := (95*a.successes + 99) / 100
		var count int64
		for _, us := range a.sortedRTTs() {
			count += a.rtts[us]
			if count >= rank {
				b.P95RTTMs = pointer(float64(us) / 1000)
				break
			}
		}
	}
	return b
}

func (a *ProbeAggregate) sortedRTTs() []int64 {
	values := make([]int64, 0, len(a.rtts))
	for us := range a.rtts {
		values = append(values, us)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values
}

// MarshalBinary uses sorted delta-coded microsecond RTTs and integer frequency
// counts. The representation is deterministic, versioned and checksummed. The
// checksum detects accidental corruption; it does not authenticate a database.
func (a *ProbeAggregate) MarshalBinary() ([]byte, error) {
	out := []byte{'V', 'P', 'A', 1}
	for _, n := range []int64{a.attempts, a.unknown, int64(len(a.rtts))} {
		out = binary.AppendUvarint(out, uint64(n))
	}
	var prev int64
	for _, us := range a.sortedRTTs() {
		out = binary.AppendUvarint(out, uint64(us-prev))
		out = binary.AppendUvarint(out, uint64(a.rtts[us]))
		prev = us
	}
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	if len(out) > MaxAggregateBytes {
		return nil, fmt.Errorf("%w: aggregate byte limit", ErrCapacity)
	}
	return out, nil
}

// DecodeProbeAggregate refuses corrupt, noncanonical, future-version and
// oversized input before publishing any counts. Work and allocation are bounded.
func DecodeProbeAggregate(data []byte) (*ProbeAggregate, error) {
	invalid := fmt.Errorf("%w: invalid aggregate encoding", ErrInvalid)
	if len(data) < 11 || len(data) > MaxAggregateBytes || !bytes.Equal(data[:4], []byte{'V', 'P', 'A', 1}) {
		return nil, invalid
	}
	payload := data[:len(data)-4]
	if binary.LittleEndian.Uint32(data[len(data)-4:]) != crc32.ChecksumIEEE(payload) {
		return nil, invalid
	}
	in := payload[4:]
	read := func(max uint64) (int64, bool) {
		n, length := binary.Uvarint(in)
		if length <= 0 || n > max || len(binary.AppendUvarint(nil, n)) != length {
			return 0, false
		}
		in = in[length:]
		return int64(n), true
	}
	attempts, ok := read(MaxAggregateSamples)
	if !ok {
		return nil, invalid
	}
	unknown, ok := read(uint64(MaxAggregateSamples - attempts))
	if !ok {
		return nil, invalid
	}
	values, ok := read(MaxAggregateRTTValues)
	if !ok || values > attempts || values > int64(len(in)/2) {
		return nil, invalid
	}
	a := &ProbeAggregate{attempts: attempts, unknown: unknown}
	if values > 0 {
		a.rtts = make(map[int64]int64, int(values))
	}
	var prev int64
	for i := int64(0); i < values; i++ {
		delta, ok := read(uint64(60_000_000 - prev))
		if !ok || (i > 0 && delta == 0) {
			return nil, invalid
		}
		us := prev + delta
		count, ok := read(uint64(attempts - a.successes))
		if !ok || count == 0 {
			return nil, invalid
		}
		a.rtts[us] = count
		a.successes += count
		a.sumUS += us * count
		prev = us
	}
	if len(in) != 0 {
		return nil, invalid
	}
	return a, nil
}
