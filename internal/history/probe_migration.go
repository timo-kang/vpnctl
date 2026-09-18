// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"database/sql"
	"fmt"
)

// v5 separates producers and preserves unavailable samples. Rebuild only the
// small streams table, retaining every ID referenced by the large probe table.
// Open owns this connection before serving requests; the transaction is atomic.
func migrateProbes(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "PRAGMA foreign_keys=ON")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
CREATE TABLE streams_v5 (
 id INTEGER PRIMARY KEY, node TEXT NOT NULL, peer TEXT NOT NULL, path TEXT NOT NULL,
 relay TEXT NOT NULL, uplink TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'legacy-probe',
 UNIQUE(node,peer,path,relay,uplink,source)
);
INSERT INTO streams_v5(id,node,peer,path,relay,uplink) SELECT id,node,peer,path,relay,uplink FROM streams;
DROP TABLE streams;
ALTER TABLE streams_v5 RENAME TO streams;
ALTER TABLE probes ADD COLUMN unknown INTEGER NOT NULL DEFAULT 0;
ALTER TABLE probes ADD COLUMN reason TEXT NOT NULL DEFAULT '';
PRAGMA user_version=5;
`)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	invalid := rows.Next()
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if invalid {
		return fmt.Errorf("history migration: invalid foreign key")
	}
	return tx.Commit()
}
