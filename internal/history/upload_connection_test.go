// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the connection lifetime across queued cancellations and successful
// transactions. The burst must leave no idle connection and survive reopening.
func TestConcurrentUploadsCancelAndReleaseConnection(t *testing.T) {
	for _, schema := range []int{5, 6, 7} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			now := time.Now().UTC()
			path := filepath.Join(t.TempDir(), "history.db")
			s, err := Open(path, now)
			if err != nil {
				t.Fatal(err)
			}
			if schema >= 6 {
				if err := s.EnableTiering(context.Background(), now); err != nil {
					t.Fatal(err)
				}
			}
			if schema == 7 {
				if err := s.EnableReclamation(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := acquire(ctx, s.writer); err != nil {
				t.Fatal(err)
			}
			held := true
			defer func() {
				if held {
					<-s.writer
				}
			}()
			const writers = 32
			canceled, committed := make(chan error, writers), make(chan error, writers)
			for i := 0; i < writers*2; i++ {
				work, results := context.Background(), committed
				if i < writers {
					work, results = ctx, canceled
				}
				o := Observation{ID: fmt.Sprint(i), PeerID: "peer", Path: "unknown", Timestamp: now.Add(-time.Duration(i) * time.Millisecond), Success: pointer(true), RTTMs: pointer(float64(i))}
				go func() { results <- s.Ingest(work, "node", []Observation{o}, now) }()
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				s.uploadMu.Lock()
				n := s.uploadUsers
				s.uploadMu.Unlock()
				if n == writers*2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("uploads did not queue")
				}
				time.Sleep(time.Millisecond)
			}
			s.uploadMu.Lock()
			db := s.uploadDB
			s.uploadMu.Unlock()
			var synchronous, foreignKeys int
			if err := db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
				t.Fatal("FULL durability lost", synchronous, err)
			}
			if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
				t.Fatal("foreign keys lost", foreignKeys, err)
			}
			cancel()
			for i := 0; i < writers; i++ {
				if err := <-canceled; !errors.Is(err, context.Canceled) {
					t.Fatal("queued cancellation", err)
				}
			}
			<-s.writer
			held = false
			for i := 0; i < writers; i++ {
				if err := <-committed; err != nil {
					t.Fatal("upload after cancellation", err)
				}
			}
			if err := db.Ping(); err == nil {
				t.Fatal("idle upload connection retained")
			}
			reopened, err := Open(path, now)
			if err != nil {
				t.Fatal(err)
			}
			latest := reopened.Latest(now)["node"]
			if len(latest) != 1 || latest[0].SampleCount != writers {
				t.Fatal("committed population", latest)
			}
			// A later isolated upload opens a fresh connection after the shared
			// connection closes, including after a transaction-level rejection.
			o := Observation{ID: "later", PeerID: "peer", Path: "unknown", Timestamp: now, Success: pointer(true), RTTMs: pointer(0.0)}
			if err := s.Ingest(context.Background(), "node", []Observation{o}, now); err != nil {
				t.Fatal(err)
			}
			o.RTTMs = pointer(1.0)
			if err := s.Ingest(context.Background(), "node", []Observation{o}, now); !errors.Is(err, ErrConflict) {
				t.Fatal("conflict", err)
			}
			o.ID = "after-conflict"
			if err := s.Ingest(context.Background(), "node", []Observation{o}, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}
