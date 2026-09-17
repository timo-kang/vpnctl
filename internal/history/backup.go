// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Backup takes a SQLite-consistent, private snapshot and publishes it without
// replacing an existing file. CLI callers also hold controller's ownership lock.
func Backup(ctx context.Context, source, destination string) error {
	if err := Check(ctx, source); err != nil {
		return err
	}
	db, err := connect(source, true)
	if err != nil {
		return err
	}
	defer db.Close()
	f, err := os.CreateTemp(filepath.Dir(destination), ".history-backup-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Close(); err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "VACUUM INTO ?", temp); err != nil {
		return err
	}
	return publish(temp, destination)
}

// Restore never overwrites an existing history database. The controller must be
// stopped; the CLI enforces this with the same lock used by controller init.
func Restore(ctx context.Context, source, destination string, now time.Time) error {
	if err := Check(ctx, source); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.CreateTemp(filepath.Dir(destination), ".history-restore-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	n, err := io.Copy(f, io.LimitReader(in, (1<<30)+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 1<<30 {
		return ErrCapacity
	}
	if err = Check(ctx, temp); err != nil {
		return err
	}
	// Opening the staged copy applies supported migrations and retention before
	// publication, and verifies that status can be recovered from its contents.
	if _, err = Open(temp, now); err != nil {
		return err
	}
	return publish(temp, destination)
}
func publish(temp, destination string) error {
	f, err := os.OpenFile(temp, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	err = f.Sync()
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err = os.Link(temp, destination); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func Check(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<30 {
		return fmt.Errorf("invalid history file (regular SQLite file <= 1 GiB required)")
	}
	db, err := connect(path, true)
	if err != nil {
		return err
	}
	defer db.Close()
	var pageSize int
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	if pageSize != 4096 {
		return fmt.Errorf("history requires 4096-byte pages")
	}
	var version, app int
	var check string
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return err
	}
	if version != 1 || app != applicationID {
		return fmt.Errorf("unsupported history backup schema %d", version)
	}
	if err = db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("history integrity: %s", check)
	}
	var rows, count, streams int64
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM probes").Scan(&rows); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "SELECT row_count FROM metadata WHERE id=1").Scan(&count); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM streams").Scan(&streams); err != nil {
		return err
	}
	if rows != count || rows > MaxRows || streams > MaxStreams {
		return fmt.Errorf("invalid history counts or capacity")
	}
	var invalid int
	if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM probes p LEFT JOIN streams s ON s.id=p.stream WHERE s.id IS NULL OR p.rtt<0 OR p.rtt>60000000)").Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("invalid history measurements")
	}
	return nil
}
