package history

import (
	"context"
	"sort"
	"time"

	"vpnctl/internal/uplink"
)

// AlertCodes and severities are fixed, independent of reporter-controlled labels.
var AlertCodes = []string{"no_uplink", "relay_failure", "persistent_loss", "stale_collector"}

func AlertSeverity(code string) string {
	if code == "no_uplink" || code == "persistent_loss" {
		return "critical"
	}
	return "warning"
}

// Alerts evaluates committed observations, not caller-supplied diagnostic events.
// Immutable, bounded snapshots keep scrapes independent of SQLite query load.
func (s *Store) Alerts(ctx context.Context, node string, now time.Time) ([]Alert, error) {
	if !validLabel(node, true) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	recent := append([]uplink.Snapshot(nil), s.uplinkRecent[node]...)
	s.mu.RUnlock()
	return evaluateAlerts(node, recent, now), nil
}

// rememberUplink requires mu held. Snapshots must be detached from caller memory.
func (s *Store) rememberUplink(node string, snapshot uplink.Snapshot) {
	recent := append(s.uplinkRecent[node], snapshot)
	sort.Slice(recent, func(i, j int) bool {
		return recent[i].At.After(recent[j].At) || recent[i].At.Equal(recent[j].At) && recent[i].ID > recent[j].ID
	})
	if len(recent) > 3 {
		recent = recent[:3:3]
	}
	s.uplinkRecent[node] = recent
	s.uplinks[node] = recent[0]
}

func evaluateAlerts(node string, recent []uplink.Snapshot, now time.Time) []Alert {
	out := make([]Alert, len(AlertCodes))
	for i, code := range AlertCodes {
		out[i] = Alert{Code: code, NodeID: node, Severity: AlertSeverity(code), Reason: "no_observation"}
	}
	if len(recent) == 0 {
		return out
	}
	latest := recent[0]
	for i := range out {
		out[i].LastSeen = latest.At
		out[i].FirstSeen = latest.At
	}
	out[3].Known = true
	out[3].Active = latest.Fresh(now).Stale
	out[3].Reason = "fresh"
	if out[3].Active {
		out[3].Reason = "observation_expired"
		if now.Before(latest.At) {
			out[3].Reason = "clock_reversed"
		}
		for i := 0; i < 3; i++ {
			out[i].Reason = "stale_observation"
		}
		return out
	}
	out[0].Known = latest.Underlay.State != "unknown"
	out[0].Active = latest.Underlay.State == "down"
	out[0].Reason = latest.Underlay.Reason
	out[1].Known = true
	out[1].Reason = "no_relay_failure"
	out[2].Known = true
	out[2].Reason = "no_persistent_loss"
	for _, target := range latest.Targets {
		if target.Relay.State == "unknown" && target.Relay.Reason != "not_configured" {
			out[1].Known = false
		}
		if target.Relay.State == "down" {
			out[1].Active = true
			out[1].Targets = append(out[1].Targets, target.ID)
		}
		if target.Service.State == "unknown" {
			out[2].Known = false
			continue
		}
		if target.Service.State != "down" {
			continue
		}
		if len(recent) < 3 {
			out[2].Known = false
			continue
		}
		persistent := true
		for i := 1; i < 3; i++ {
			interval := time.Duration(recent[i-1].IntervalSec) * time.Second
			gap := recent[i-1].At.Sub(recent[i].At)
			// Completion jitter must not reset an otherwise continuous outage.
			if gap < interval/2 || gap >= 3*interval {
				out[2].Known = false
				persistent = false
				break
			}
			found := false
			for _, old := range recent[i].Targets {
				if old.ID == target.ID && old.Protocol == target.Protocol && old.Service.State == "down" {
					found = true
				}
			}
			if !found {
				persistent = false
				break
			}
		}
		if persistent {
			out[2].Active = true
			out[2].Targets = append(out[2].Targets, target.ID)
			out[2].FirstSeen = recent[2].At
		}
	}
	if !out[1].Known {
		out[1].Reason = "unknown_relay_state"
	}
	if !out[2].Known {
		out[2].Reason = "insufficient_recent_evidence"
	}
	// Evidence of any failed target is sufficient even if another is unknown.
	if out[1].Active {
		out[1].Known = true
		out[1].Reason = "relay_probe_failed"
	}
	if out[2].Active {
		out[2].Known = true
		out[2].Reason = "three_consecutive_failed_cycles"
	}
	return out
}
