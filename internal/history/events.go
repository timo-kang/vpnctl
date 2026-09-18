// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"vpnctl/internal/metrics"
	"vpnctl/internal/uplink"
)

const (
	MaxEvents     = 1_000_000
	MaxNodeEvents = 50_400 // one event every five seconds for seven days
	MaxEventText  = 256
)

const eventSchema = `
CREATE TABLE IF NOT EXISTS events(
 node TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL,
 kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
 previous TEXT NOT NULL DEFAULT '', current TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL, validity TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(node,id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS event_time ON events(ts,id);
CREATE INDEX IF NOT EXISTS event_node_time ON events(node,ts,id);
CREATE TABLE IF NOT EXISTS event_metadata(id INTEGER PRIMARY KEY CHECK(id=1), row_count INTEGER NOT NULL);
INSERT OR IGNORE INTO event_metadata VALUES(1,0);
PRAGMA user_version=3;
`

// Event is an immutable state transition or diagnostic signal. Labels are
// intentionally bounded so event history cannot become an unbounded-cardinality
// metrics or storage input.
type Event struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Target    string    `json:"target,omitempty"`
	Previous  string    `json:"previous,omitempty"`
	Current   string    `json:"current,omitempty"`
	Severity  string    `json:"severity"`
	Validity  string    `json:"validity"`
	Message   string    `json:"message,omitempty"`
}

type EventHistory struct {
	SchemaVersion int       `json:"schema_version"`
	NodeID        string    `json:"node_id"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Events        []Event   `json:"events"`
	Truncated     bool      `json:"truncated"`
}

type Alert struct {
	Code      string    `json:"code"`
	NodeID    string    `json:"node_id"`
	Severity  string    `json:"severity"`
	Active    bool      `json:"active"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Reason    string    `json:"reason"`
}

type EventStorage interface {
	IngestEvent(context.Context, string, Event, time.Time) error
	QueryEvents(context.Context, string, time.Time, time.Duration, int) (EventHistory, error)
	Alerts(context.Context, string, time.Time) ([]Alert, error)
}

var eventKinds = map[string]bool{
	"route_change":    true,
	"relay_failover":  true,
	"uplink_change":   true,
	"nat_remap":       true,
	"certificate":     true,
	"discovery_error": true,
	"probe_error":     true,
	"collector_error": true,
}

func validEventText(v string, required bool) bool {
	return validLabel(v, required) && len(v) <= MaxEventText
}

func validateEvent(node string, event Event, now time.Time) error {
	if !validLabel(node, true) || !validLabel(event.ID, true) || !validLabel(event.Source, true) || !validLabel(event.Target, false) || !validLabel(event.Previous, false) || !validLabel(event.Current, false) || !validEventText(event.Message, false) {
		return fmt.Errorf("%w: invalid event identity or text", ErrInvalid)
	}
	if !eventKinds[event.Kind] || (event.Severity != "info" && event.Severity != "warning" && event.Severity != "critical") || (event.Validity != "observed" && event.Validity != "inferred" && event.Validity != "unknown") {
		return fmt.Errorf("%w: invalid event kind, severity or validity", ErrInvalid)
	}
	event.Timestamp = event.Timestamp.UTC()
	if event.Timestamp.IsZero() || event.Timestamp.After(now) || !event.Timestamp.After(now.Add(-Retention)) {
		return fmt.Errorf("%w: event timestamp must be in (now-7d, now]", ErrInvalid)
	}
	return nil
}

func eventID(e Event) string {
	s := strings.Join([]string{e.NodeID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.Kind, e.Source, e.Target, e.Previous, e.Current, e.Severity, e.Validity, e.Message}, "\x00")
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s *Store) IngestEvent(ctx context.Context, node string, event Event, now time.Time) error {
	now = now.UTC().Truncate(time.Microsecond)
	event.NodeID = node
	event.Timestamp = event.Timestamp.UTC().Truncate(time.Microsecond)
	if event.ID == "" {
		event.ID = eventID(event)
	}
	if err := validateEvent(node, event, now); err != nil {
		return err
	}
	if err := acquire(ctx, s.writer); err != nil {
		return err
	}
	defer func() { <-s.writer }()
	db, err := connect(s.path, false)
	if err != nil {
		return err
	}
	defer db.Close()
	if now.Sub(s.lastCleanup) >= time.Minute {
		if err = s.maintainDB(ctx, db, now); err != nil {
			return err
		}
	}
	if err = s.limitWAL(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	inserted, err := insertEventTx(ctx, tx, node, event)
	if err != nil {
		return err
	}
	if inserted {
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func insertEventTx(ctx context.Context, tx *sql.Tx, node string, event Event) (bool, error) {
	var existing Event
	var existingTS int64
	err := tx.QueryRowContext(ctx, `SELECT id,ts,kind,source,target,previous,current,severity,validity,message FROM events WHERE node=? AND id=?`, node, event.ID).Scan(&existing.ID, &existingTS, &existing.Kind, &existing.Source, &existing.Target, &existing.Previous, &existing.Current, &existing.Severity, &existing.Validity, &existing.Message)
	if err == nil {
		if existingTS == event.Timestamp.UnixMicro() && existing.Kind == event.Kind && existing.Source == event.Source && existing.Target == event.Target && existing.Previous == event.Previous && existing.Current == event.Current && existing.Severity == event.Severity && existing.Validity == event.Validity && existing.Message == event.Message {
			return false, nil
		}
		return false, ErrConflict
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	var count, nodeCount int
	if err = tx.QueryRowContext(ctx, "SELECT row_count FROM event_metadata WHERE id=1").Scan(&count); err != nil {
		return false, err
	}
	if count >= MaxEvents {
		return false, ErrCapacity
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE node=?", node).Scan(&nodeCount); err != nil {
		return false, err
	}
	if nodeCount >= MaxNodeEvents {
		return false, ErrCapacity
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(node,id,ts,kind,source,target,previous,current,severity,validity,message) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, node, event.ID, event.Timestamp.UnixMicro(), event.Kind, event.Source, event.Target, event.Previous, event.Current, event.Severity, event.Validity, event.Message)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE event_metadata SET row_count=row_count+1 WHERE id=1")
	if err == nil {
		metrics.EventTotal.WithLabelValues(event.Kind, event.Severity, "accepted").Inc()
	}
	return true, err
}

func (s *Store) QueryEvents(ctx context.Context, node string, end time.Time, window time.Duration, limit int) (EventHistory, error) {
	end = end.UTC().Truncate(time.Microsecond)
	out := EventHistory{SchemaVersion: 1, NodeID: node, Start: end.Add(-window), End: end, Events: []Event{}}
	if !validLabel(node, true) || window <= 0 || window > Retention || limit < 1 || limit > 1000 {
		return out, ErrInvalid
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
	rows, err := db.QueryContext(ctx, `SELECT id,ts,kind,source,target,previous,current,severity,validity,message FROM events WHERE node=? AND ts>? AND ts<=? ORDER BY ts DESC,id DESC LIMIT ?`, node, out.Start.UnixMicro(), end.UnixMicro(), limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		var ts int64
		if err = rows.Scan(&e.ID, &ts, &e.Kind, &e.Source, &e.Target, &e.Previous, &e.Current, &e.Severity, &e.Validity, &e.Message); err != nil {
			return out, err
		}
		e.NodeID, e.Timestamp = node, time.UnixMicro(ts).UTC()
		out.Events = append(out.Events, e)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if len(out.Events) > limit {
		out.Truncated = true
		out.Events = out.Events[:limit]
	}
	return out, nil
}

func alertForEvent(e Event, node string) (code string, trigger bool, resolved bool) {
	switch {
	case e.Kind == "uplink_change":
		return "no_uplink", e.Current == "down" || e.Current == "unknown", e.Current == "up"
	case e.Kind == "relay_failover":
		return "relay_failure", e.Current == "down" || e.Current == "unknown", e.Current == "up"
	case e.Kind == "probe_error":
		return "persistent_loss", strings.HasPrefix(e.Current, "down"), strings.HasPrefix(e.Current, "up")
	case e.Kind == "collector_error":
		return "stale_collector", e.Current == "stale" || e.Current == "down", e.Current == "up"
	default:
		return "", false, false
	}
}

func (s *Store) Alerts(ctx context.Context, node string, now time.Time) ([]Alert, error) {
	events, err := s.latestAlertEvents(ctx, node, now)
	if err != nil {
		return nil, err
	}
	states := map[string]Alert{}
	for _, e := range events { // one newest transition per alert code defines current state
		code, trigger, resolved := alertForEvent(e, node)
		if code == "" {
			continue
		}
		if _, seen := states[code]; seen {
			continue
		}
		a := Alert{Code: code, NodeID: node, Severity: e.Severity, Active: trigger, FirstSeen: e.Timestamp, LastSeen: e.Timestamp, Reason: e.Message}
		if resolved {
			a.Active = false
		}
		states[code] = a
	}
	order := []string{"no_uplink", "relay_failure", "persistent_loss", "stale_collector"}
	defaultSeverity := map[string]string{"no_uplink": "critical", "relay_failure": "warning", "persistent_loss": "critical", "stale_collector": "warning"}
	out := make([]Alert, 0, len(order))
	for _, code := range order {
		a, ok := states[code]
		severity := defaultSeverity[code]
		active := 0.0
		if !ok {
			a = Alert{Code: code, NodeID: node, Severity: severity}
		}
		out = append(out, a)
		if a.Active {
			active = 1
		}
		metrics.AlertActive.WithLabelValues(code, severity).Set(active)
	}
	return out, nil
}

func (s *Store) latestAlertEvents(ctx context.Context, node string, now time.Time) ([]Event, error) {
	if !validLabel(node, true) {
		return nil, ErrInvalid
	}
	now = now.UTC().Truncate(time.Microsecond)
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
	rows, err := db.QueryContext(ctx, `SELECT id,ts,kind,source,target,previous,current,severity,validity,message
		FROM events WHERE node=? AND ts>? AND ts<=? AND kind IN ('uplink_change','relay_failover','probe_error','collector_error')
		ORDER BY kind,ts DESC,id DESC`, node, now.Add(-Retention).UnixMicro(), now.UnixMicro())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err = rows.Scan(&e.ID, &ts, &e.Kind, &e.Source, &e.Target, &e.Previous, &e.Current, &e.Severity, &e.Validity, &e.Message); err != nil {
			return nil, err
		}
		if seen[e.Kind] {
			continue
		}
		seen[e.Kind] = true
		e.NodeID, e.Timestamp = node, time.UnixMicro(ts).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) maintainEvents(ctx context.Context, db *sql.DB, now time.Time) error {
	for {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM events WHERE (node,id) IN (SELECT node,id FROM events WHERE ts<=? LIMIT 1000)`, now.Add(-Retention).UnixMicro())
		if err != nil {
			tx.Rollback()
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE event_metadata SET row_count=row_count-? WHERE id=1", n); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if n < 1000 {
			return nil
		}
	}
}

func deriveUplinkEvents(node string, previous *uplink.Snapshot, current uplink.Snapshot) []Event {
	makeEvent := func(kind, target, prev, curr, severity, message string) Event {
		return Event{NodeID: node, Timestamp: current.At, Kind: kind, Source: "uplink-observer", Target: target, Previous: prev, Current: curr, Severity: severity, Validity: "observed", Message: message}
	}
	var events []Event
	prevUnderlay := ""
	if previous != nil {
		prevUnderlay = previous.Underlay.State
	}
	if previous == nil || prevUnderlay != current.Underlay.State {
		severity := "info"
		if current.Underlay.State != "up" {
			severity = "critical"
		}
		events = append(events, makeEvent("uplink_change", "underlay", prevUnderlay, current.Underlay.State, severity, current.Underlay.Reason))
	}
	if previous != nil {
		for _, link := range current.Links {
			var old string
			for _, p := range previous.Links {
				if p.ID == link.ID {
					old = p.Controller.State
					break
				}
			}
			if old != link.Controller.State {
				kind, severity := "uplink_change", "info"
				if link.Controller.State != "up" {
					kind, severity = "collector_error", "warning"
				}
				events = append(events, makeEvent(kind, link.ID, old, link.Controller.State, severity, link.Controller.Reason))
			}
		}
	}
	for _, target := range current.Targets {
		var old uplink.Target
		found := false
		if previous != nil {
			for _, p := range previous.Targets {
				if p.ID == target.ID {
					old, found = p, true
					break
				}
			}
		}
		if !found {
			old.FailureStage = ""
		}
		oldRoute := old.TransportRoute.Interface + ":" + old.TransportRoute.Gateway
		newRoute := target.TransportRoute.Interface + ":" + target.TransportRoute.Gateway
		if !found || oldRoute != newRoute {
			events = append(events, makeEvent("route_change", target.ID, oldRoute, newRoute, "info", target.TransportRoute.Reason))
		}
		if !found || old.RelayPeerFingerprint != target.RelayPeerFingerprint || old.Relay.State != target.Relay.State {
			severity := "info"
			if target.Relay.State != "up" {
				severity = "warning"
			}
			events = append(events, makeEvent("relay_failover", target.ID, old.Relay.State, target.Relay.State, severity, target.Relay.Reason))
		}
		if !found || old.Service.State != target.Service.State || old.FailureStage != target.FailureStage {
			severity := "info"
			if target.Service.State == "down" {
				severity = "critical"
			}
			events = append(events, makeEvent("probe_error", target.ID, old.Service.State+":"+old.FailureStage, target.Service.State+":"+target.FailureStage, severity, target.Service.Reason))
		}
	}
	return events
}
