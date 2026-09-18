package history

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestControllerEventsMigrateBackupRestartAndClockSkew(t *testing.T) {
	s, now := legacyStore(t, 3)
	ctx := context.Background()
	db, err := connect(s.path, false)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the v3 predecessor; v4 changes ownership semantics, not columns.
	_, err = db.Exec("PRAGMA user_version=3")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	s, err = Open(s.path, now)
	if err != nil {
		t.Fatal(err)
	}
	e := Event{ID: "one", Timestamp: now.Add(-time.Second), Kind: "certificate", Source: "controller-pki", Current: "ca.prepare:success", Severity: "info", Validity: "observed"}
	if err = s.IngestEvent(ctx, "", e, now); err != nil {
		t.Fatal(err)
	}
	e.ID = "older"
	e.Timestamp = now.Add(-2 * time.Second)
	if err = s.IngestEvent(ctx, "", e, now); err != nil {
		t.Fatal(err)
	}
	future := e
	future.ID = "future"
	future.Timestamp = now.Add(time.Second)
	if !errors.Is(s.IngestEvent(ctx, "", future, now), ErrInvalid) {
		t.Fatal("future timestamp accepted")
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err = Backup(ctx, s.path, backup); err != nil {
		t.Fatal(err)
	}
	if err = Check(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err = Restore(ctx, backup, restored, now); err != nil {
		t.Fatal(err)
	}
	s, err = Open(restored, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.IngestEvent(ctx, "", e, now); err != nil {
		t.Fatal(err)
	}
	out, err := s.QueryEvents(ctx, "", now, time.Hour, 10)
	if err != nil || out.Scope != "controller" || len(out.Events) != 2 || out.Events[0].ID != "one" {
		t.Fatal(out, err)
	}
	db, err = connect(restored, true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 5 {
		t.Fatal(version, err)
	}
}
