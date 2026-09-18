package history

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"vpnctl/internal/metrics"
	"vpnctl/internal/uplink"
)

func alertMap(t *testing.T, s *Store, node string, now time.Time) map[string]Alert {
	t.Helper()
	alerts, err := s.Alerts(context.Background(), node, now)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Alert{}
	for _, a := range alerts {
		out[a.Code] = a
	}
	return out
}

func TestReviewAlertEvidence(t *testing.T) {
	for _, scenario := range []string{"single_failure", "other_target_recovers", "unknown", "stopped_collector", "forged_recovery", "repeated_timestamp", "cycle_jitter", "clock_reversed"} {
		t.Run(scenario, func(t *testing.T) {
			s, now := newStore(t)
			for i := 0; i < 3; i++ {
				v := uplinkFixture(now.Add(time.Duration(i-2)*time.Minute), fmt.Sprintf("sample-%d", i))
				v.Targets[0].Relay = uplink.Down("timeout")
				v.Targets[0].Service = uplink.Down("timeout")
				v.Targets[0].FailureStage = "relay_tunnel"
				switch scenario {
				case "single_failure":
					if i < 2 {
						v = uplinkFixture(v.At, v.ID)
					}
				case "other_target_recovers":
					other := v.Targets[0]
					other.ID = "other"
					if i == 2 {
						other.Relay = uplink.Up()
						other.Service = uplink.Check{State: "up", RTTMs: pointer(1.)}
						other.FailureStage = "none"
					}
					v.Targets = append(v.Targets, other)
				case "unknown":
					v.Underlay = uplink.Unknown("permission_denied")
					v.Targets[0].Relay = uplink.Unknown("permission_denied")
					v.Targets[0].Service = uplink.Unknown("permission_denied")
				case "cycle_jitter":
					v.At = now.Add(time.Duration(i-2) * (time.Minute - time.Millisecond))
				case "repeated_timestamp":
					v.At = now
				}
				if err := s.IngestUplink(context.Background(), "robot", v, now); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "forged_recovery" {
				e := Event{Timestamp: now, Kind: "relay_failover", Source: "agent", Target: "server", Current: "up", Severity: "info", Validity: "observed"}
				if err := s.IngestEvent(context.Background(), "robot", e, now); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "clock_reversed" {
				now = now.Add(-time.Second)
			}
			if scenario == "stopped_collector" {
				now = now.Add(3 * time.Minute)
			}
			for pass := 0; pass < 2; pass++ {
				a := alertMap(t, s, "robot", now)
				switch scenario {
				case "single_failure", "repeated_timestamp":
					if a["persistent_loss"].Active {
						t.Fatal("isolated failure counted as persistent", a)
					}
				case "other_target_recovers", "forged_recovery", "cycle_jitter":
					if !a["relay_failure"].Active || !a["persistent_loss"].Active {
						t.Fatal("failure hidden by another recovery", a)
					}
				case "unknown":
					if a["no_uplink"].Active || a["relay_failure"].Active {
						t.Fatal("unknown counted as down", a)
					}
				case "stopped_collector", "clock_reversed":
					if !a["stale_collector"].Active {
						t.Fatal("silence did not trigger staleness", a)
					}
				}
				var err error
				s, err = Open(s.path, now)
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestReviewRolledBackEventNotAccepted(t *testing.T) {
	s, now := newStore(t)
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	counter := metrics.EventTotal.WithLabelValues("certificate", "info", "accepted")
	before := counterValue(counter)
	e := Event{ID: "rollback", Timestamp: now, Kind: "certificate", Source: "agent", Severity: "info", Validity: "observed"}
	if _, err = insertEventTx(context.Background(), tx, "robot", e); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if counterValue(counter) != before {
		t.Fatal("rolled back event counted as accepted")
	}
}

func TestReviewRelayIdentityAndRouteChanges(t *testing.T) {
	old := uplinkFixture(time.Now().Add(-time.Minute), "old")
	old.Targets[0].RelayPeerFingerprint = "relay-a"
	next := uplinkFixture(time.Now(), "next")
	next.Targets[0].RelayPeerFingerprint = "relay-b"
	next.Targets[0].Route.Source = "10.0.0.2"
	events := deriveUplinkEvents("robot", &old, next)
	relay, route := false, false
	for _, e := range events {
		if e.Kind == "relay_failover" && e.Previous != e.Current {
			relay = true
		}
		if e.Kind == "route_change" {
			route = true
		}
	}
	if !relay || !route {
		t.Fatalf("lost relay identity or overlay change: %+v", events)
	}
}

func counterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	_ = c.Write(&m)
	return m.GetCounter().GetValue()
}
