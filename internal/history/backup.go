// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	if (version < 1 || version > 6) || app != applicationID {
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
	streamLimit, nodeLimit := MaxStreams, MaxNodeStreams
	if version == 6 {
		streamLimit, nodeLimit = TieredMaxStreams, TieredMaxNodeStreams
		if err = checkTiered(ctx, db); err != nil {
			return err
		}
	}
	if rows != count || rows > MaxRows || streams > int64(streamLimit) {
		return fmt.Errorf("invalid history counts or capacity")
	}
	var invalid int
	if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM probes p LEFT JOIN streams s ON s.id=p.stream WHERE s.id IS NULL OR p.rtt<0 OR p.rtt>60000000)").Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("invalid history measurements")
	}
	if version >= 5 {
		if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM probes WHERE unknown NOT IN (0,1) OR (unknown=1 AND (rtt IS NOT NULL OR length(reason)=0)) OR (rtt IS NOT NULL AND reason!='') OR length(reason)>64)`).Scan(&invalid); err != nil {
			return err
		}
		if invalid != 0 {
			return fmt.Errorf("invalid probe validity")
		}
		if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM streams WHERE source NOT IN ('legacy-probe','cli-ping','agent-direct','monitor-overlay'))`).Scan(&invalid); err != nil {
			return err
		}
		if invalid != 0 {
			return fmt.Errorf("invalid probe source")
		}
		streams, e := readStreams(ctx, db, "")
		if e != nil {
			return e
		}
		counts := map[string]int{}
		for _, st := range streams {
			counts[st.NodeID]++
			if counts[st.NodeID] > nodeLimit {
				return ErrCapacity
			}
			o := Observation{ID: "check", Timestamp: time.Now().UTC(), PeerID: st.PeerID, Path: st.Path, RelayID: st.RelayID, Uplink: st.Uplink, Source: st.Source, Success: pointer(false)}
			if err := Validate(st.NodeID, o, o.Timestamp); err != nil {
				return err
			}
		}
		reasons, e := db.QueryContext(ctx, "SELECT DISTINCT reason FROM probes WHERE reason!=''")
		if e != nil {
			return e
		}
		for reasons.Next() {
			var reason string
			if e = reasons.Scan(&reason); e != nil {
				reasons.Close()
				return e
			}
			if !validLabel(reason, false) || len(reason) > 64 {
				reasons.Close()
				return fmt.Errorf("invalid stored probe reason")
			}
		}
		e = reasons.Err()
		reasons.Close()
		if e != nil {
			return e
		}

	}
	if version >= 2 {
		var stored, actual, bad int
		if err = db.QueryRowContext(ctx, "SELECT row_count FROM uplink_metadata WHERE id=1").Scan(&stored); err != nil {
			return err
		}
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM uplink_snapshots").Scan(&actual); err != nil {
			return err
		}
		if stored != actual || actual > MaxUplinkSnapshots {
			return fmt.Errorf("invalid uplink history counts")
		}
		if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM uplink_results r LEFT JOIN uplink_snapshots s ON (s.node,s.id)=(r.node,r.id) WHERE s.id IS NULL OR r.state NOT IN ('up','down','unknown') OR r.rtt<0 OR r.rtt>60000 OR (r.state!='up' AND r.rtt IS NOT NULL) OR (r.state='up' AND r.rtt IS NULL) OR r.ts!=s.ts)").Scan(&bad); err != nil {
			return err
		}
		if bad != 0 {
			return fmt.Errorf("invalid uplink history results")
		}
		if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM uplink_latest l LEFT JOIN uplink_snapshots s ON (s.node,s.id)=(l.node,l.id) WHERE s.id IS NULL OR s.ts!=l.ts OR s.payload!=l.payload)").Scan(&bad); err != nil {
			return err
		}
		if bad != 0 {
			return fmt.Errorf("invalid latest uplink snapshot")
		}
		records, e := db.QueryContext(ctx, "SELECT node,id,ts,payload,digest FROM uplink_snapshots")
		if e != nil {
			return e
		}
		for records.Next() {
			var node, id string
			var ts int64
			var payload, digest []byte
			if e = records.Scan(&node, &id, &ts, &payload, &digest); e != nil {
				records.Close()
				return e
			}
			snapshot, e := unpackSnapshot(payload)
			if e != nil {
				records.Close()
				return e
			}
			raw, _ := json.Marshal(snapshot)
			sum := sha256.Sum256(raw)
			if !validLabel(node, true) || snapshot.ID != id || snapshot.At.UnixMicro() != ts || snapshot.Validate(snapshot.At) != nil || !bytes.Equal(sum[:], digest) {
				records.Close()
				return fmt.Errorf("invalid stored uplink snapshot")
			}
		}
		e = records.Err()
		records.Close()
		if e != nil {
			return e
		}
	}
	if version >= 3 {
		var stored, actual int
		if err = db.QueryRowContext(ctx, "SELECT row_count FROM event_metadata WHERE id=1").Scan(&stored); err != nil {
			return err
		}
		if err = db.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&actual); err != nil {
			return err
		}
		if stored != actual || actual > MaxEvents {
			return fmt.Errorf("invalid event history counts")
		}
		var bad int
		if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM events WHERE kind NOT IN ('route_change','relay_failover','uplink_change','nat_remap','certificate','discovery_error','probe_error','collector_error') OR severity NOT IN ('info','warning','critical') OR validity NOT IN ('observed','inferred','unknown') OR length(id)=0)").Scan(&bad); err != nil {
			return err
		}
		if bad != 0 {
			return fmt.Errorf("invalid stored event")
		}
		if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM events GROUP BY node HAVING count(*) > ?)", MaxNodeEvents).Scan(&bad); err != nil {
			return err
		}
		if bad != 0 {
			return fmt.Errorf("event history node capacity exceeded")
		}
		rows, e := db.QueryContext(ctx, `SELECT node,id,ts,kind,source,target,previous,current,severity,validity,message FROM events`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var event Event
			var ts int64
			if e = rows.Scan(&event.NodeID, &event.ID, &ts, &event.Kind, &event.Source, &event.Target, &event.Previous, &event.Current, &event.Severity, &event.Validity, &event.Message); e != nil {
				rows.Close()
				return e
			}
			event.Timestamp = time.UnixMicro(ts).UTC()
			// Historical age is checked by retention on restore, not against wall time.
			if ts <= 0 || version < 4 && event.NodeID == "" || validateEvent(event.NodeID, event, event.Timestamp) != nil {
				rows.Close()
				return fmt.Errorf("invalid stored event")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}

	}

	return nil
}
