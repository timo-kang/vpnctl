// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Sixfold JSON escaping of maximum-length labels must still fit the response
// budget at 200 buckets per stream. The bound applies before materialization.
const MaxPageStreams = 16
const MaxHistoryResponseBytes = 16 << 20

type PageRequest struct {
	Node, Source  string
	End           time.Time
	Window, Width time.Duration // zero Width selects the supported default
	Cursor        string
	Align         bool // explicitly allow rounding an archived window down to UTC hours
}

type PageInfo struct {
	RequestedStart      time.Time `json:"requested_start"`
	RequestedEnd        time.Time `json:"requested_end"`
	SealedUntil         time.Time `json:"sealed_until"`
	ExpiredUntil        time.Time `json:"expired_until"`
	RawRetentionSeconds int64     `json:"raw_retention_seconds"`
	AggregateSeconds    int64     `json:"aggregate_seconds"`
	Aligned             bool      `json:"aligned"`
	NextCursor          string    `json:"next_cursor,omitempty"`
	StreamLimit         int       `json:"stream_limit"`
}

type HistoryPage struct {
	PageInfo
	Start, End time.Time
	Width      time.Duration
	Buckets    []Bucket
}

type pageCursor struct {
	Version       int `json:"v"`
	Node, Source  string
	End           time.Time
	Window, Width time.Duration
	Align         bool
	After         int64
}

// QueryPage uses one read snapshot per page. The cursor fixes the requested
// window/filter, but does not claim a cross-request database snapshot: concurrent
// ingestion, expiry and stream churn remain visible between pages.
func (s *Store) QueryPage(ctx context.Context, req PageRequest) (HistoryPage, error) {
	var out HistoryPage
	if !s.Tiered() {
		return out, fmt.Errorf("%w: tiering is not enabled", ErrInvalid)
	}
	if !validLabel(req.Node, false) {
		return out, ErrInvalid
	}
	switch req.Source {
	case "", "legacy-probe", "cli-ping", "agent-direct", "monitor-overlay":
	default:
		return out, ErrInvalid
	}
	after := int64(0)
	if req.Cursor != "" {
		if len(req.Cursor) > 2048 {
			return out, ErrInvalid
		}
		data, err := base64.RawURLEncoding.DecodeString(req.Cursor)
		if err != nil {
			return out, ErrInvalid
		}
		var c pageCursor
		if json.Unmarshal(data, &c) != nil || c.Version != 1 || c.After <= 0 || c.Node != req.Node || c.Source != req.Source || c.Window != req.Window || c.Width != req.Width || c.Align != req.Align || (!req.End.IsZero() && !req.End.Equal(c.End)) {
			return out, fmt.Errorf("%w: cursor does not match query", ErrInvalid)
		}
		after = c.After
		req.End = c.End
	}
	if req.End.IsZero() {
		req.End = time.Now().UTC()
	}
	req.End = req.End.UTC().Truncate(time.Microsecond)
	if req.End.UnixMicro() <= 0 {
		return out, ErrInvalid
	}
	width := req.Width
	if width == 0 {
		width = DefaultWidth(req.Window)
	}
	if err := ValidateQuery(req.Window, width); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	if err := acquire(ctx, s.query); err != nil {
		return out, err
	}
	defer func() { <-s.query }()
	db, err := connect(s.path, true)
	if err != nil {
		return out, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var seal, expired int64
	if err = tx.QueryRowContext(ctx, "SELECT sealed_until,expired_until FROM tier_metadata WHERE id=1").Scan(&seal, &expired); err != nil {
		return out, err
	}
	out.PageInfo = PageInfo{RequestedStart: req.End.Add(-req.Window), RequestedEnd: req.End, SealedUntil: time.UnixMicro(seal).UTC(), ExpiredUntil: time.UnixMicro(expired).UTC(), RawRetentionSeconds: int64(CandidateRawRetention.Seconds()), AggregateSeconds: 3600, StreamLimit: MaxPageStreams}
	out.End = req.End
	if out.RequestedStart.UnixMicro() < seal {
		if req.Width == 0 && width < time.Hour {
			width = time.Hour
		}
		if req.Window%time.Hour != 0 || width%time.Hour != 0 {
			return out, fmt.Errorf("%w: sealed history requires whole-hour window and buckets", ErrInvalid)
		}
		if !out.End.Equal(out.End.Truncate(time.Hour)) {
			if !req.Align {
				return out, fmt.Errorf("%w: sealed history requires UTC-hour boundaries", ErrInvalid)
			}
			out.End = out.End.Truncate(time.Hour)
			out.Aligned = true
		}
	}
	out.Start = out.End.Add(-req.Window)
	out.Width = width
	if out.Start.UnixMicro() < expired {
		return out, fmt.Errorf("%w: requested history has expired through %s", ErrInvalid, out.ExpiredUntil.Format(time.RFC3339))
	}
	q := `SELECT id,node,peer,path,relay,uplink,source FROM streams WHERE id>?`
	args := []any{after}
	if req.Node != "" {
		q += " AND node=?"
		args = append(args, req.Node)
	}
	if req.Source != "" {
		q += " AND source=?"
		args = append(args, req.Source)
	}
	q += " ORDER BY id LIMIT ?"
	args = append(args, MaxPageStreams+1)
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return out, err
	}
	var streams []streamRow
	for rows.Next() {
		var st streamRow
		if err = rows.Scan(&st.id, &st.NodeID, &st.PeerID, &st.Path, &st.RelayID, &st.Uplink, &st.Source); err != nil {
			break
		}
		streams = append(streams, st)
	}
	e := rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if e != nil {
		return out, e
	}
	if len(streams) > MaxPageStreams {
		streams = streams[:MaxPageStreams]
		data, e := json.Marshal(pageCursor{Version: 1, Node: req.Node, Source: req.Source, End: req.End, Window: req.Window, Width: req.Width, Align: req.Align, After: streams[len(streams)-1].id})
		if e != nil {
			return out, e
		}
		out.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	out.Buckets = []Bucket{}
	seen := 0
	for _, st := range streams {
		n := int((req.Window + width - 1) / width)
		agg := make([]ProbeAggregate, n)
		rows, err = tx.QueryContext(ctx, "SELECT end_ts,payload FROM rollups WHERE stream=? AND end_ts>? AND end_ts<=? ORDER BY end_ts", st.id, out.Start.UnixMicro(), out.End.UnixMicro())
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var end int64
			var payload []byte
			if err = rows.Scan(&end, &payload); err != nil {
				break
			}
			var a *ProbeAggregate
			a, err = DecodeProbeAggregate(payload)
			if err != nil {
				err = fmt.Errorf("corrupt stored history aggregate: %v", err)
				break
			}
			i := int((end - out.Start.UnixMicro() - 1) / width.Microseconds())
			if i < 0 || i >= n || end-time.Hour.Microseconds() < out.Start.UnixMicro()+int64(i)*width.Microseconds() {
				err = fmt.Errorf("%w: aggregate crosses query boundary", ErrInvalid)
				break
			}
			if err = agg[i].Merge(a); err != nil {
				break
			}
		}
		e = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		if e != nil {
			return out, e
		}
		rows, err = tx.QueryContext(ctx, "SELECT ts,rtt,unknown FROM probes WHERE stream=? AND ts>? AND ts<=?", st.id, out.Start.UnixMicro(), out.End.UnixMicro())
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var ts int64
			var rtt sql.NullInt64
			var unknown bool
			if err = rows.Scan(&ts, &rtt, &unknown); err != nil {
				break
			}
			seen++
			if seen > MaxRows {
				err = ErrCapacity
				break
			}
			i := int((ts - out.Start.UnixMicro() - 1) / width.Microseconds())
			success := pointer(rtt.Valid)
			var ms *float64
			if unknown {
				success = nil
			}
			if rtt.Valid {
				ms = pointer(float64(rtt.Int64) / 1000)
			}
			if err = agg[i].Add(success, ms); err != nil {
				break
			}
		}
		e = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		if e != nil {
			return out, e
		}
		for i := range agg {
			if err = ctx.Err(); err != nil {
				return out, err
			}
			out.Buckets = append(out.Buckets, agg[i].Bucket(st.Stream, out.Start.Add(time.Duration(i)*width)))
		}
	}
	return out, ctx.Err()
}
