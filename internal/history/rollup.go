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

	"vpnctl/internal/quality"
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
// IDs or reasons. Ordered v2 summaries also retain jitter and timestamp
// boundaries. They cannot reconstruct partial intervals or live quality state.
// Its zero value is empty; callers must not copy it after first use or use it
// concurrently. Use the binary representation for detached snapshots.
type ProbeAggregate struct {
	orderedEncoding                     bool
	unordered                           int64
	jitter                              quality.JitterSummary
	attempts, unknown, successes, sumUS int64
	rtts                                map[int64]int64
}

// Add preserves the same numeric semantics as raw history: unknown is outside
// the attempt denominator; successful zero RTT is a measurement, not missing.
// Any rejected update leaves the aggregate unchanged.
func (a *ProbeAggregate) Add(success *bool, rttMS *float64) error {
	if err := a.add(success, rttMS); err != nil {
		return err
	}
	a.unordered++
	a.jitter = quality.JitterSummary{}
	return nil
}

// AddAt requires nondecreasing timestamps. Equal timestamps are ambiguous
// barriers; stable ID order cannot establish their physical observation order.
func (a *ProbeAggregate) AddAt(at int64, success *bool, rttMS *float64) error {
	if at <= 0 || (a.unordered == 0 && a.jitter.Samples > 0 && at < a.jitter.Last.At) {
		return fmt.Errorf("%w: unordered jitter population", ErrInvalid)
	}
	if err := a.add(success, rttMS); err != nil {
		return err
	}
	a.orderedEncoding = true
	if a.unordered == 0 {
		us := int64(0)
		ok := success != nil && *success
		if ok {
			us = int64(math.Round(*rttMS * 1000))
		}
		a.jitter.Add(at, us, ok)
	}
	return nil
}

func (a *ProbeAggregate) add(success *bool, rttMS *float64) error {
	if a.attempts+a.unknown >= MaxAggregateSamples {
		return &QuotaError{Resource: "aggregate_samples", Limit: MaxAggregateSamples}
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
			return &QuotaError{Resource: "aggregate_rtt_values", Limit: MaxAggregateRTTValues}
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
		return &QuotaError{Resource: "aggregate_samples", Limit: MaxAggregateSamples}
	}
	combined := a.jitter
	if a.unordered+b.unordered == 0 {
		if combined.Samples > 0 && b.jitter.Samples > 0 && (b.jitter.First.At < combined.First.At || (b.jitter.First.At == combined.First.At && b.jitter.Last.At < combined.Last.At)) {
			combined = b.jitter
			if !combined.Append(a.jitter) {
				return fmt.Errorf("%w: overlapping jitter populations", ErrInvalid)
			}
		} else if !combined.Append(b.jitter) {
			return fmt.Errorf("%w: overlapping jitter populations", ErrInvalid)
		}
	} else {
		combined = quality.JitterSummary{}
	}
	newValues := len(a.rtts)
	for us := range b.rtts {
		if _, exists := a.rtts[us]; !exists {
			newValues++
		}
	}
	if newValues > MaxAggregateRTTValues {
		return &QuotaError{Resource: "aggregate_rtt_values", Limit: MaxAggregateRTTValues}
	}
	if len(b.rtts) > 0 && a.rtts == nil {
		a.rtts = make(map[int64]int64, newValues)
	}
	for us, n := range b.rtts {
		a.rtts[us] += n
	}
	a.jitter = combined
	a.unordered += b.unordered
	a.orderedEncoding = a.orderedEncoding || b.orderedEncoding
	a.attempts += b.attempts
	a.unknown += b.unknown
	a.successes += b.successes
	a.sumUS += b.sumUS
	return nil
}

// Bucket produces the raw API's exact average and nearest-rank p50/p95/p99. Its caller
// owns stream identity and interval boundaries; only whole aggregate intervals
// may be included in the population.
func (a *ProbeAggregate) Bucket(stream Stream, start time.Time) Bucket {
	b := Bucket{Stream: stream, Time: start, Count: int(a.attempts), UnknownCount: int(a.unknown), Successes: int(a.successes)}
	b.JitterStats = a.jitter.Stats()
	if a.unordered > 0 {
		b.JitterStats = quality.JitterStats{JitterStatus: "unavailable_order", JitterKnownSamples: a.attempts + a.unknown - a.unordered}
	}
	if a.attempts > 0 {
		b.AvailabilityPct = pointer(100 * float64(a.successes) / float64(a.attempts))
		b.LossPct = pointer(100 - *b.AvailabilityPct)
	}
	if a.successes > 0 {
		b.AvgRTTMs = pointer(float64(a.sumUS) / float64(a.successes) / 1000)
		percentiles := []int{50, 95, 99}
		values := []**float64{&b.P50RTTMs, &b.P95RTTMs, &b.P99RTTMs}
		next := 0
		var count int64
		for _, us := range a.sortedRTTs() {
			count += a.rtts[us]
			for next < len(percentiles) && count >= int64(quality.PercentileRank(int(a.successes), percentiles[next])) {
				*values[next] = pointer(float64(us) / 1000)
				next++
			}
			if next == len(percentiles) {
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
	if a.orderedEncoding {
		out[3] = 2
	}
	for _, n := range []int64{a.attempts, a.unknown, int64(len(a.rtts))} {
		out = binary.AppendUvarint(out, uint64(n))
	}
	var prev int64
	for _, us := range a.sortedRTTs() {
		out = binary.AppendUvarint(out, uint64(us-prev))
		out = binary.AppendUvarint(out, uint64(a.rtts[us]))
		prev = us
	}
	if a.orderedEncoding {
		out = binary.AppendUvarint(out, uint64(a.unordered))
		if a.unordered == 0 && a.attempts+a.unknown > 0 {
			j := a.jitter
			for _, v := range []int64{j.Groups, j.First.At, j.First.Count, j.First.RTTUS + 1, j.Last.At - j.First.At, j.Last.Count, j.Last.RTTUS + 1, j.Total.Pairs, j.Total.SumUS, j.Head.Pairs, j.Head.SumUS, j.Tail.Pairs, j.Tail.SumUS} {
				out = binary.AppendUvarint(out, uint64(v))
			}
		}
	}
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	if len(out) > MaxAggregateBytes {
		return nil, &QuotaError{Resource: "aggregate_bytes", Limit: MaxAggregateBytes}
	}
	return out, nil
}

// DecodeProbeAggregate refuses corrupt, noncanonical, future-version and
// oversized input before publishing any counts. Work and allocation are bounded.
func DecodeProbeAggregate(data []byte) (*ProbeAggregate, error) {
	invalid := fmt.Errorf("%w: invalid aggregate encoding", ErrInvalid)
	if len(data) < 11 || len(data) > MaxAggregateBytes || !bytes.Equal(data[:3], []byte{'V', 'P', 'A'}) || (data[3] != 1 && data[3] != 2) {
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
	a.unordered = attempts + unknown
	if data[3] == 2 {
		a.orderedEncoding = true
		a.unordered, ok = read(uint64(attempts + unknown))
		if !ok {
			return nil, invalid
		}
		if a.unordered == 0 && attempts+unknown > 0 {
			var v [13]int64
			for i := range v {
				v[i], ok = read(math.MaxInt64)
				if !ok {
					return nil, invalid
				}
			}
			if v[4] > math.MaxInt64-v[1] {
				return nil, invalid
			}
			a.jitter = quality.JitterSummary{Samples: attempts + unknown, Groups: v[0],
				First: quality.JitterGroup{At: v[1], Count: v[2], RTTUS: v[3] - 1},
				Last:  quality.JitterGroup{At: v[1] + v[4], Count: v[5], RTTUS: v[6] - 1},
				Total: quality.JitterEdge{Pairs: v[7], SumUS: v[8]},
				Head:  quality.JitterEdge{Pairs: v[9], SumUS: v[10]},
				Tail:  quality.JitterEdge{Pairs: v[11], SumUS: v[12]}}
			if !validJitter(a.jitter, a.successes) {
				return nil, invalid
			}
			for _, g := range []quality.JitterGroup{a.jitter.First, a.jitter.Last} {
				if g.RTTUS >= 0 && a.rtts[g.RTTUS] == 0 {
					return nil, invalid
				}
			}
		}
	}
	if len(in) != 0 {
		return nil, invalid
	}
	return a, nil
}
