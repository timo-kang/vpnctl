// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/modemsignal"
)

func TestModemSignalsPersistenceAndLegacyCompatibility(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	v := uplinkFixture(now, "signals")
	v.Links[0].Kind = "lte"
	signal := modemsignal.Parse("modem.signal.lte.snr : 0\nmodem.signal.lte.rsrq : --", now.Add(-time.Second+123*time.Nanosecond))
	signal.ReadAt = signal.ReadAt.In(time.FixedZone("fixture", 9*3600))
	v.Links[0].ModemSignals = &signal
	if err := s.IngestUplink(ctx, "robot", v, now); err != nil {
		t.Fatal(err)
	}
	if v.Links[0].ModemSignals != &signal || signal.ReadAt.Location() == time.UTC || signal.ReadAt.Nanosecond()%1000 != 123 {
		t.Fatal("ingestion mutated source")
	}
	signal.ReadAt = signal.ReadAt.UTC()
	if err := s.IngestUplink(ctx, "robot", v, now); err != nil {
		t.Fatal("timezone changed digest", err)
	}
	*signal.LTE.SNR.Value = 1
	if err := s.IngestUplink(ctx, "robot", v, now); !errors.Is(err, ErrConflict) {
		t.Fatal("changed RF value idempotently accepted", err)
	}
	s, err = Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	query, err := s.QueryUplinks(ctx, "robot", now, time.Hour, 10)
	if err != nil || len(query.Snapshots) != 1 {
		t.Fatal(query, err)
	}
	got := query.Snapshots[0].Links[0].ModemSignals
	if got == nil || got.MeasurementTime != "unavailable" || got.LTE.SNR.Value == nil || *got.LTE.SNR.Value != 0 || got.LTE.RSRQ.Value != nil || got.ReadAt.Location() != time.UTC || got.ReadAt.Nanosecond()%1000 != 0 {
		t.Fatal("RF persistence lost source semantics", got)
	}
	*got.LTE.SNR.Value = 9
	if *s.LatestUplinks(now)["robot"].Links[0].ModemSignals.LTE.SNR.Value != 0 {
		t.Fatal("RF query aliases live cache")
	}
	latest := s.LatestUplinks(now.Add(179 * time.Second))["robot"]
	if latest.Stale || !latest.Links[0].ModemSignals.ReadStale {
		t.Fatal("older RF read age hidden", latest)
	}
	if err := s.IngestUplink(ctx, "robot", uplinkFixture(now, "legacy"), now); err != nil {
		t.Fatal("legacy ingestion rejected", err)
	}
}

func TestModemSignalsRejectsRawFutureAndInvalid(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s, err := Open(filepath.Join(t.TempDir(), "history.db"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"future", "inconsistent", "stale-read"} {
		v := uplinkFixture(now, kind)
		v.Links[0].Kind = "lte"
		signal := modemsignal.Parse("modem.signal.lte.snr : 0", now)
		switch kind {
		case "future":
			signal.ReadAt = now.Add(time.Nanosecond)
		case "inconsistent":
			signal.LTE.SNR.State = "missing"
		case "stale-read":
			signal.ReadStale = true
		}
		v.Links[0].ModemSignals = &signal
		if err := s.IngestUplink(context.Background(), "robot", v, now); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid RF observation admitted", kind, err)
		}
	}
	if len(s.LatestUplinks(now)) != 0 {
		t.Fatal("rejected data published")
	}
}
