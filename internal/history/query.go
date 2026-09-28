// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"time"
)

func DefaultWidth(window time.Duration) time.Duration {
	if window <= time.Hour {
		return time.Minute
	}
	if window <= 24*time.Hour {
		return 15 * time.Minute
	}
	return time.Hour
}
func ValidateQuery(window, width time.Duration) error {
	if window <= 0 || window > Retention {
		return fmt.Errorf("%w: window must be in (0,168h]", ErrInvalid)
	}
	if width < time.Minute || width > window || width%time.Minute != 0 || int64(math.Ceil(float64(window)/float64(width))) > 200 {
		return fmt.Errorf("%w: bucket width must be whole minutes, <= window, and produce <= 200 buckets per stream", ErrInvalid)
	}
	return nil
}

// Query returns complete buckets, including null-valued gaps, for every retained
// stream in scope. The query is a single SQLite read snapshot. A cancelled or
// over-budget query returns an error, never a partial successful response.
func (s *Store) Query(ctx context.Context, node string, end time.Time, window, width time.Duration) ([]Bucket, error) {
	if s.Tiered() {
		page, err := s.QueryPage(ctx, PageRequest{Node: node, End: end, Window: window, Width: width})
		if err != nil {
			return nil, err
		}
		if page.NextCursor != "" {
			return nil, fmt.Errorf("%w: use paginated history", ErrCapacity)
		}
		return page.Buckets, nil
	}
	if err := ValidateQuery(window, width); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	if err := acquire(ctx, s.query); err != nil {
		return nil, err
	}
	defer func() { <-s.query }()
	db, err := connect(s.path, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	streams, err := readStreams(ctx, tx, node)
	if err != nil {
		return nil, err
	}
	if len(streams) > MaxStreams {
		return nil, ErrCapacity
	}
	start := end.Add(-window)
	n := int(math.Ceil(float64(window) / float64(width)))
	out := make([]Bucket, 0, len(streams)*n)
	seen := 0
	for _, st := range streams {
		buckets := make([]Bucket, n)
		rtts := make([][]int64, n)
		sums := make([]int64, n)
		for i := range buckets {
			buckets[i] = Bucket{Stream: st.Stream, Time: start.Add(time.Duration(i) * width).UTC()}
		}
		rows, e := tx.QueryContext(ctx, "SELECT ts,rtt,unknown FROM probes WHERE stream=? AND ts>? AND ts<=?", st.id, start.UnixMicro(), end.UnixMicro())
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var ts int64
			var rtt sql.NullInt64
			var unknown bool
			if e = rows.Scan(&ts, &rtt, &unknown); e != nil {
				rows.Close()
				return nil, e
			}
			seen++
			if seen > MaxRows {
				rows.Close()
				return nil, ErrCapacity
			}
			i := int((ts - start.UnixMicro() - 1) / width.Microseconds())
			b := &buckets[i]
			if unknown {
				b.UnknownCount++
				continue
			}
			b.Count++
			if rtt.Valid {
				b.Successes++
				sums[i] += rtt.Int64
				rtts[i] = append(rtts[i], rtt.Int64)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for i := range buckets {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			b := &buckets[i]
			if b.Count > 0 {
				b.AvailabilityPct = pointer(100 * float64(b.Successes) / float64(b.Count))
				b.LossPct = pointer(100 - *b.AvailabilityPct)
			}
			if b.Successes > 0 {
				b.AvgRTTMs = pointer(float64(sums[i]) / float64(b.Successes) / 1000)
				sort.Slice(rtts[i], func(a, b int) bool { return rtts[i][a] < rtts[i][b] })
				rank := (95*b.Successes + 99) / 100
				b.P95RTTMs = pointer(float64(rtts[i][rank-1]) / 1000)
			}
		}
		out = append(out, buckets...)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
