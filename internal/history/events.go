// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vpnctl/internal/metrics"
	"vpnctl/internal/uplink"
)

const (
	MaxEvents     = 1_000_000
	MaxNodeEvents = 50_400 // bounded diagnostic history; high transition rates may hit this before seven days
	MaxEventText  = 256
)

const eventSchema = `
CREATE TABLE events(
 node TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL,
 kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
 previous TEXT NOT NULL DEFAULT '', current TEXT NOT NULL DEFAULT '',
 severity TEXT NOT NULL, validity TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(node,id)
) WITHOUT ROWID;
CREATE INDEX event_time ON events(ts,id);
CREATE INDEX event_node_time ON events(node,ts,id);
CREATE TABLE event_metadata(id INTEGER PRIMARY KEY CHECK(id=1), row_count INTEGER NOT NULL);
INSERT INTO event_metadata VALUES(1,0);
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
	Known     bool      `json:"known"`
	Targets   []string  `json:"targets,omitempty"`
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
	return boundedEventText(v, required, MaxEventText)
}

func boundedEventText(v string, required bool, max int) bool {
	if !utf8.ValidString(v) || len(v) > max || required && strings.TrimSpace(v) == "" {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateEvent(node string, event Event, now time.Time) error {
	if !validLabel(node, true) || !validLabel(event.ID, true) || !validLabel(event.Source, true) || !validLabel(event.Target, false) || !boundedEventText(event.Previous, false, 2048) || !boundedEventText(event.Current, false, 2048) || !validEventText(event.Message, false) {
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
		metrics.EventTotal.WithLabelValues(event.Kind, event.Severity, "accepted").Inc()
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

func (s *Store) maintainEvents(ctx context.Context, db *sql.DB, now time.Time) error {
	for {
		if err := s.limitWAL(ctx, db); err != nil {
			return err
		}
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
				kind, severity := "collector_error", "info"
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
		oldRoute := routeIdentity(old)
		newRoute := routeIdentity(target)
		if !found || oldRoute != newRoute {
			events = append(events, makeEvent("route_change", target.ID, oldRoute, newRoute, "info", target.TransportRoute.Reason))
		}
		if !found || relayIdentity(old) != relayIdentity(target) {
			severity := "info"
			if target.Relay.State != "up" {
				severity = "warning"
			}
			events = append(events, makeEvent("relay_failover", target.ID, relayIdentity(old), relayIdentity(target), severity, target.Relay.Reason))
		}
		if !found || old.Service.State != target.Service.State || old.FailureStage != target.FailureStage || old.Protocol != target.Protocol {
			severity := "info"
			if target.Service.State == "down" {
				severity = "critical"
			}
			events = append(events, makeEvent("probe_error", target.ID, old.Service.State+":"+old.FailureStage, target.Service.State+":"+target.FailureStage, severity, target.Service.Reason))
		}
	}
	if previous != nil {
		for _, old := range previous.Targets {
			found := false
			for _, target := range current.Targets {
				if old.ID == target.ID {
					found = true
					break
				}
			}
			if !found {
				events = append(events, makeEvent("route_change", old.ID, routeIdentity(old), "removed", "info", "target_removed"), makeEvent("relay_failover", old.ID, relayIdentity(old), "removed", "info", "target_removed"), makeEvent("probe_error", old.ID, old.Service.State, "removed", "info", "target_removed"))
			}
		}
	}
	return events
}

func routeIdentity(t uplink.Target) string {
	overlay, transport := t.Route, t.TransportRoute
	overlay.RTTMs, transport.RTTMs = nil, nil
	raw, _ := json.Marshal(struct {
		Overlay   uplink.Route `json:"overlay"`
		Transport uplink.Route `json:"transport"`
	}{overlay, transport})
	return string(raw)
}
func relayIdentity(t uplink.Target) string {
	raw, _ := json.Marshal(struct {
		State    string `json:"state"`
		Reason   string `json:"reason,omitempty"`
		Expected string `json:"expected_id,omitempty"`
		Peer     string `json:"peer_fingerprint,omitempty"`
	}{t.Relay.State, t.Relay.Reason, t.ExpectedRelayID, t.RelayPeerFingerprint})
	return string(raw)
}
