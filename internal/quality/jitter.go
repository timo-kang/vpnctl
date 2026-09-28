// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package quality

import "fmt"

// JitterStats describes RTT variation in the retained observation population.
// Complete means ordering is available, not that delivery was lossless. Nil
// pairs means legacy ordering is unavailable; zero pairs means no valid pair.
type JitterStats struct {
	JitterMs           *float64 `json:"jitter_ms"`
	JitterPairs        *int64   `json:"jitter_pair_count"`
	JitterKnownSamples int64    `json:"jitter_known_samples"`
	JitterStatus       string   `json:"jitter_status"`
}

func (s JitterStats) Clone() JitterStats {
	s.JitterMs, s.JitterPairs = copyPtr(s.JitterMs), copyPtr(s.JitterPairs)
	return s
}

// JitterGroup is one timestamp group. Ties are ambiguous and break both
// adjacent edges, regardless of ID order. RTTUS is -1 for failures/unknown/ties.
type JitterGroup struct{ At, Count, RTTUS int64 }
type JitterEdge struct{ Pairs, SumUS int64 }

// JitterSummary is a constant-space ordered summary. Boundary edges allow a
// timestamp group split across compaction batches to invalidate earlier pairs.
// Callers must supply disjoint populations in timestamp order, deduplicate IDs
// and isolate streams/windows. No sequence or delivery completeness is inferred.
type JitterSummary struct {
	Samples, Groups   int64
	First, Last       JitterGroup
	Total, Head, Tail JitterEdge
}

func jitterEdge(a, b JitterGroup) JitterEdge {
	if a.At >= b.At || a.Count != 1 || b.Count != 1 || a.RTTUS < 0 || b.RTTUS < 0 {
		return JitterEdge{}
	}
	d := a.RTTUS - b.RTTUS
	if d < 0 {
		d = -d
	}
	return JitterEdge{1, d}
}

// Append returns false without mutation for overlapping/out-of-order ranges.
// Equal boundary timestamps are merged into one ambiguous group.
func (a *JitterSummary) Append(b JitterSummary) bool {
	if b.Samples == 0 {
		return true
	}
	if a.Samples == 0 {
		*a = b
		return true
	}
	if a.Last.At > b.First.At {
		return false
	}
	out := JitterSummary{Samples: a.Samples + b.Samples, Groups: a.Groups + b.Groups, First: a.First, Last: b.Last,
		Total: JitterEdge{a.Total.Pairs + b.Total.Pairs, a.Total.SumUS + b.Total.SumUS}, Head: a.Head, Tail: b.Tail}
	if a.Last.At < b.First.At {
		e := jitterEdge(a.Last, b.First)
		out.Total.Pairs += e.Pairs
		out.Total.SumUS += e.SumUS
		if a.Groups == 1 {
			out.Head = e
		}
		if b.Groups == 1 {
			out.Tail = e
		}
	} else {
		out.Groups--
		out.Total.Pairs -= a.Tail.Pairs + b.Head.Pairs
		out.Total.SumUS -= a.Tail.SumUS + b.Head.SumUS
		tie := JitterGroup{a.Last.At, a.Last.Count + b.First.Count, -1}
		if a.Groups == 1 {
			out.First = tie
		}
		if b.Groups == 1 {
			out.Last = tie
		}
		if a.Groups <= 2 {
			out.Head = JitterEdge{}
		}
		if b.Groups <= 2 {
			out.Tail = JitterEdge{}
		}
	}
	*a = out
	return true
}

func (a *JitterSummary) Add(at, rttUS int64, success bool) bool {
	if !success {
		rttUS = -1
	}
	p := JitterGroup{at, 1, rttUS}
	return a.Append(JitterSummary{Samples: 1, Groups: 1, First: p, Last: p})
}

func (a JitterSummary) Stats() JitterStats {
	s := JitterStats{JitterPairs: ptr(a.Total.Pairs), JitterKnownSamples: a.Samples, JitterStatus: "complete"}
	if a.Total.Pairs > 0 {
		s.JitterMs = ptr(float64(a.Total.SumUS) / float64(a.Total.Pairs) / 1000)
	}
	return s
}

// JitterText is shared by terminal and controller HTML consumers.
func (s JitterStats) JitterText() string {
	value, pairs := "-", "-"
	if s.JitterMs != nil {
		value = fmt.Sprintf("%.2f", *s.JitterMs)
	}
	if s.JitterPairs != nil {
		pairs = fmt.Sprint(*s.JitterPairs)
	}
	state := s.JitterStatus
	if state == "" {
		state = "unavailable_order"
	}
	return fmt.Sprintf("jitter(ms)=%s pairs=%s known=%d %s", value, pairs, s.JitterKnownSamples, state)
}
