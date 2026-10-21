// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictorinput

import (
	"fmt"
	"reflect"
	"slices"
	"time"

	"vpnctl/internal/history"
	"vpnctl/internal/predictor"
)

// BuildProbes consumes one authenticated node's exact M2 history stream. It
// accepts unsorted delivery and identical duplicate IDs, but rejects conflicts,
// mixed streams, future samples and invalid measurements. It does not turn peer
// probe RTT into a target-server latency or infer bandwidth from byte counters.
func BuildProbes(stream history.Stream, input []history.Observation, now time.Time, cfg Config) (Result, error) {
	// Event-time alignment must not depend on process-local monotonic readings.
	now = now.Round(0).UTC()
	if now.IsZero() || cfg.RTTWindow <= 0 || cfg.RTTWindow > MaxWindow ||
		cfg.LossWindow <= 0 || cfg.LossWindow > MaxWindow || cfg.Bucket < time.Microsecond ||
		cfg.Bucket > min(cfg.RTTWindow, cfg.LossWindow) || cfg.MaxAge <= 0 ||
		cfg.MaxAge > min(cfg.RTTWindow, cfg.LossWindow) || len(input) > MaxSamples || stream.Source == "" {
		return Result{}, ErrInvalid
	}
	// Reuse the canonical M2 label/source/path validator for the declared scope,
	// including an empty input. This schema check is never emitted as a sample.
	failed := false
	shape := history.Observation{ID: "scope", Source: stream.Source, PeerID: stream.PeerID,
		Path: stream.Path, RelayID: stream.RelayID, Uplink: stream.Uplink, Timestamp: now, Success: &failed}
	if err := history.Validate(stream.NodeID, shape, now); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	rows := make([]history.Observation, 0, len(input))
	seen := make(map[string]history.Observation, len(input))
	for _, raw := range input {
		// Validate before canonicalization so sub-microsecond future/invalid times
		// cannot be rounded back into an accepted measurement.
		if err := history.Validate(stream.NodeID, raw, now); err != nil {
			return Result{}, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		o := raw.Canonicalize()
		if o.Timestamp.IsZero() {
			return Result{}, ErrInvalid
		}
		if o.Source != stream.Source || o.PeerID != stream.PeerID || o.Path != stream.Path || o.RelayID != stream.RelayID || o.Uplink != stream.Uplink {
			return Result{}, fmt.Errorf("%w: mixed probe streams", ErrInvalid)
		}
		if old, exists := seen[o.ID]; exists {
			if !reflect.DeepEqual(old, o) {
				return Result{}, history.ErrConflict
			}
			continue
		}
		seen[o.ID] = o
		rows = append(rows, o)
	}
	slices.SortFunc(rows, func(a, b history.Observation) int {
		if n := a.Timestamp.Compare(b.Timestamp); n != 0 {
			return n
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	out := Result{Stream: stream, Observation: predictor.Observation{Now: now.UTC(), Known: new([predictor.SignalCount]bool)}, Reason: "no_usable_probe_measurement"}
	for i := range out.Features {
		out.Features[i] = Feature{Source: "none", State: "missing", Reason: "not_collected"}
	}
	out.Observation.RTTHistory, out.Features[predictor.SignalRTT] = probeWindow(rows, stream.Source, now, cfg.RTTWindow, cfg, false)
	out.Observation.LossHistory, out.Features[predictor.SignalLoss] = probeWindow(rows, stream.Source, now, cfg.LossWindow, cfg, true)
	for _, i := range []int{predictor.SignalRTT, predictor.SignalLoss} {
		out.Observation.Known[i] = out.Features[i].State == "observed"
		out.Ready = out.Ready || out.Observation.Known[i]
	}
	if out.Ready {
		out.Reason = ""
	}
	return out, nil
}

type probeBucket struct {
	at                          time.Time
	last                        history.Observation
	attempts, failures, unknown int
	lastFailed, lastUnknown     bool
}

func probeWindow(rows []history.Observation, source string, now time.Time, window time.Duration, cfg Config, loss bool) ([]predictor.Sample, Feature) {
	feature := Feature{Source: source, State: "missing", Reason: "no_samples"}
	if len(rows) == 0 {
		return nil, feature
	}
	latest := rows[len(rows)-1]
	at, age := latest.Timestamp, int64(now.Sub(latest.Timestamp))
	feature.ObservedAt, feature.AgeNS = &at, &age
	var buckets []probeBucket
	cutoff := now.Add(-window)
	for _, o := range rows {
		if !o.Timestamp.After(cutoff) {
			continue
		}
		feature.InputCount++
		edge := o.Timestamp.Truncate(cfg.Bucket)
		if len(buckets) == 0 || !buckets[len(buckets)-1].at.Equal(edge) {
			buckets = append(buckets, probeBucket{at: edge})
		}
		b := &buckets[len(buckets)-1]
		if !o.Timestamp.Equal(b.last.Timestamp) {
			b.lastFailed, b.lastUnknown = false, false
		}
		b.last = o
		b.lastUnknown = b.lastUnknown || o.Success == nil
		b.lastFailed = b.lastFailed || o.Success != nil && !*o.Success
		if o.Success == nil {
			b.unknown++
			feature.UnknownCount++
		} else {
			b.attempts++
			if !*o.Success {
				b.failures++
			}
		}
	}
	if now.Sub(latest.Timestamp) >= cfg.MaxAge {
		feature.State, feature.Reason = "stale", "sample_expired"
		return nil, feature
	}
	// Simultaneous conflicting outcomes cannot become healthy by sorting IDs.
	last := buckets[len(buckets)-1]
	if last.lastUnknown {
		feature.State, feature.Reason = "unknown", "probe_unknown"
		return nil, feature
	}
	if !loss && last.lastFailed {
		feature.Reason = "probe_failed"
		return nil, feature
	}
	if loss && buckets[len(buckets)-1].unknown > 0 {
		feature.State, feature.Reason = "unknown", "unknown_in_bucket"
		return nil, feature
	}
	samples := make([]predictor.Sample, 0, len(buckets))
	for _, b := range buckets {
		if loss {
			// Do not recalculate a partially expired bucket after its failed or
			// unknown inputs leave the window. No new event means no new ratio.
			if !b.at.After(cutoff) {
				continue
			}
			// Unknown outcomes do not silently shrink the loss denominator. Omit the
			// entire affected bucket; metadata retains how many inputs were unknown.
			if b.unknown == 0 && b.attempts > 0 {
				samples = append(samples, predictor.Sample{At: b.last.Timestamp, Value: 100 * float64(b.failures) / float64(b.attempts)})
			}
		} else if !b.lastUnknown && !b.lastFailed {
			samples = append(samples, predictor.Sample{At: b.last.Timestamp, Value: *b.last.RTTMs})
		}
	}
	if len(samples) == 0 {
		feature.Reason = "partial_window_bucket"
		return nil, feature
	}
	feature.State, feature.Reason = "observed", ""
	return samples, feature
}
