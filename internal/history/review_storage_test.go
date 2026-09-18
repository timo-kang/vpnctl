package history

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/uplink"
)

func TestReviewEventQuotaDoesNotBlockObservation(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?) INSERT INTO events SELECT 'robot',cast(i AS TEXT),?,'certificate','agent','','','','info','observed','' FROM n`, MaxNodeEvents, now.UnixMicro())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE event_metadata SET row_count=?`, MaxNodeEvents); err != nil {
		t.Fatal(err)
	}
	e := Event{Timestamp: now, Kind: "certificate", Source: "agent", Severity: "info", Validity: "observed"}
	if err = s.IngestEvent(ctx, "robot", e, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("quota not enforced: %v", err)
	}
	snapshot := uplinkFixture(now, "at-capacity")
	snapshot.Underlay = uplink.Down("no_route")
	if err = s.IngestUplink(ctx, "robot", snapshot, now); err != nil {
		t.Fatalf("diagnostic quota blocked telemetry: %v", err)
	}
	if !alertMap(t, s, "robot", now)["no_uplink"].Active {
		t.Fatal("quota hid outage")
	}
	if err = Check(ctx, s.path); err != nil {
		t.Fatal(err)
	}
}

func TestReviewConcurrentAndReorderedSnapshotReplay(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := uplinkFixture(now.Add(time.Duration(i-39)*time.Minute), fmt.Sprintf("sample-%02d", i))
			v.Targets[0].RelayPeerFingerprint = fmt.Sprintf("relay-%02d", i)
			v.Targets[0].Service = uplink.Down("timeout")
			v.Targets[0].FailureStage = "server_endpoint"
			if err := s.IngestUplink(ctx, "robot", v, now); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	before := alertMap(t, s, "robot", now)
	reopened, err := Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, alertMap(t, reopened, "robot", now)) {
		t.Fatal("replay differs from live cache")
	}
	if s.LatestUplinks(now)["robot"].ID != "sample-39" {
		t.Fatal("cache moved backwards")
	}
	h, err := s.QueryEvents(ctx, "robot", now, time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var transitions []Event
	for _, e := range h.Events {
		if e.Kind == "relay_failover" {
			transitions = append(transitions, e)
		}
	}
	for i := 0; i < len(transitions)-1; i++ {
		if transitions[i].Previous != transitions[i+1].Current {
			t.Fatalf("concurrent ingest lost predecessor: %+v", transitions)
		}
	}
	if !before["persistent_loss"].Active {
		t.Fatal("last three consecutive failures not reconstructed")
	}
}

func TestReviewBackupRejectsCorruptEvent(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	e := Event{ID: "one", Timestamp: now, Kind: "certificate", Source: "agent", Severity: "info", Validity: "observed"}
	if err := s.IngestEvent(ctx, "robot", e, now); err != nil {
		t.Fatal(err)
	}
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`UPDATE events SET message=?`, strings.Repeat("x", MaxEventText+1)); err != nil {
		t.Fatal(err)
	}
	if err = Check(ctx, s.path); err == nil {
		t.Fatal("oversized event passed backup integrity check")
	}
}
