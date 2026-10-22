// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestLegacyJitterSortPreservesPopulationAcrossRuns(t *testing.T) {
	for _, size := range []int{0, 1, 4095, 4096, 4097, 12345} {
		for _, order := range []string{"sorted", "reverse", "shuffled"} {
			t.Run(fmt.Sprintf("%d/%s", size, order), func(t *testing.T) {
				samples := make([]legacyJitterSample, size)
				for i := range samples {
					samples[i] = legacyJitterSample{at: int64(i / 3), rttUS: int64(i%17 - 1)}
				}
				if order == "reverse" {
					slices.Reverse(samples)
				} else if order == "shuffled" {
					rand.New(rand.NewSource(265)).Shuffle(size, func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
				}
				want := slices.Clone(samples)
				if err := sortLegacyJitter(context.Background(), samples); err != nil {
					t.Fatal(err)
				}
				if !slices.IsSortedFunc(samples, func(a, b legacyJitterSample) int { return cmp.Compare(a.at, b.at) }) {
					t.Fatal("timestamps not sorted")
				}
				// Ties have no observable order; compare their full value multiset.
				byValue := func(a, b legacyJitterSample) int {
					if c := cmp.Compare(a.at, b.at); c != 0 {
						return c
					}
					return cmp.Compare(a.rttUS, b.rttUS)
				}
				slices.SortFunc(samples, byValue)
				slices.SortFunc(want, byValue)
				if !slices.Equal(samples, want) {
					t.Fatal("sort changed sample population")
				}
			})
		}
	}
}

// Cancel after sorting has started, deterministically exercising checks during
// both run sorting and merging without relying on scheduler timing.
type jitterSortCancelContext struct {
	context.Context
	cancel        context.CancelFunc
	checks, after int
}

func (c *jitterSortCancelContext) Err() error {
	c.checks++
	if c.checks == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestLegacyJitterSortHonorsCancellationDuringWork(t *testing.T) {
	for _, after := range []int{1, 6, 12} {
		ctx, cancel := context.WithCancel(context.Background())
		c := &jitterSortCancelContext{Context: ctx, cancel: cancel, after: after}
		samples := make([]legacyJitterSample, 32768)
		for i := range samples {
			samples[i].at = int64(len(samples) - i)
		}
		err := sortLegacyJitter(c, samples)
		cancel()
		if !errors.Is(err, context.Canceled) || c.checks != after {
			t.Fatalf("after=%d checks=%d err=%v", after, c.checks, err)
		}
	}
}

func TestLegacyFullRetentionMatchesIndexedDailyWindows(t *testing.T) {
	s, now := newStore(t)
	end := now.Truncate(time.Hour)
	start := end.Add(-Retention)
	for node := 0; node < 2; node++ {
		var observations []Observation
		ids := rand.New(rand.NewSource(int64(265 + node))).Perm(168 * 8)
		for hour := 0; hour < 168; hour++ {
			for sample := 0; sample < 8; sample++ {
				second := sample + 1
				if sample == 3 {
					second = 3 // Duplicate timestamp with different RTT.
				}
				o := obs(fmt.Sprintf("id-%04d", ids[hour*8+sample]), start.Add(time.Duration(hour)*time.Hour+time.Duration(second)*time.Second), pointer(float64(node*100+sample*sample)))
				if sample == 5 {
					o.Success, o.RTTMs = pointer(false), nil
				}
				if sample == 7 {
					o.Success, o.RTTMs, o.Validity, o.Reason = nil, nil, "unknown", "collector_unavailable"
				}
				observations = append(observations, o)
			}
		}
		slices.Reverse(observations)
		for batch := 0; batch < len(observations); batch += MaxBatch {
			ingest(t, s, fmt.Sprintf("robot-%d", node), observations[batch:min(batch+MaxBatch, len(observations))], end)
		}
	}
	var want []Bucket
	for node := 0; node < 2; node++ {
		for day := 1; day <= 7; day++ {
			bs, err := s.Query(context.Background(), fmt.Sprintf("robot-%d", node), start.Add(time.Duration(day)*24*time.Hour), 24*time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, bs...)
		}
	}
	got, err := s.Query(context.Background(), "", end, Retention, time.Hour)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("full retention differs from indexed daily windows: err=%v buckets=%d want=%d", err, len(got), len(want))
	}
}
