// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"vpnctl/internal/controller"
)

type monitorHistorySnapshot struct {
	Attempts  int      `json:"attempts"`
	Successes int      `json:"successes"`
	Unknown   int      `json:"unknown"`
	WGIDs     []string `json:"wireguard_ids"`
}

// This fixture uses the default raw history schema and stops its only monitor.
// Hold the controller's ownership lock while taking one read-only SQL snapshot:
// producer cancellation alone does not drain a server-side commit. Do not use
// history.Open here: it would migrate/expire records before measuring them.
func readStoppedMonitorHistory(ctx context.Context, dataDir string, now time.Time) (monitorHistorySnapshot, error) {
	out := monitorHistorySnapshot{WGIDs: []string{}}
	lock, err := controller.AcquireStateLock(dataDir)
	if err != nil {
		return out, err
	}
	defer lock.Close()
	u := url.URL{Scheme: "file", Path: filepath.Join(dataDir, "history.db")}
	q := u.Query()
	q.Set("mode", "ro")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return out, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	start, end := now.Add(-time.Hour).UnixMicro(), now.UnixMicro()
	var invalid int
	err = tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(p.unknown=0),0),
		COALESCE(SUM(p.unknown=0 AND p.rtt IS NOT NULL),0),
		COALESCE(SUM(p.unknown=1),0),
		COALESCE(SUM(s.peer!='node-1' OR s.path!='unknown' OR s.relay!='' OR s.uplink!=''),0)
		FROM probes p JOIN streams s ON s.id=p.stream
		WHERE s.node='node-0' AND s.source='monitor-overlay' AND p.ts>? AND p.ts<=?`, start, end).
		Scan(&out.Attempts, &out.Successes, &out.Unknown, &invalid)
	if err != nil {
		return out, err
	}
	if invalid != 0 {
		return out, fmt.Errorf("stopped monitor history contains %d invalid route identities", invalid)
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM wireguard_reports WHERE node='node-0' AND ts>? AND ts<=? ORDER BY id", start, end)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return out, err
		}
		out.WGIDs = append(out.WGIDs, id)
	}
	return out, rows.Err()
}
