// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package history

import (
	"context"
	"fmt"
	"time"
)

// checkTiered validates the committed format, including partially completed
// compaction. Neither opening nor restoring assumes a maintenance run finished.
func checkTiered(ctx context.Context, db reader) error {
	var seal, expired, rowCount, byteCount, compacted, last int64
	if err := db.QueryRowContext(ctx, `SELECT sealed_until,expired_until,rollup_rows,rollup_bytes,compacted_samples,last_compaction FROM tier_metadata WHERE id=1`).Scan(&seal, &expired, &rowCount, &byteCount, &compacted, &last); err != nil {
		return err
	}
	hour := time.Hour.Microseconds()
	if seal <= 0 || seal%hour != 0 || expired < 0 || expired%hour != 0 || expired > seal || rowCount < 0 || rowCount > MaxRollupRows || byteCount < 0 || byteCount > MaxRollupStorageBytes || compacted < 0 || last < 0 {
		return fmt.Errorf("invalid tier metadata")
	}
	var invalid int
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM rollups r LEFT JOIN streams s ON s.id=r.stream WHERE s.id IS NULL OR r.end_ts<=0 OR r.end_ts%3600000000!=0 OR r.end_ts>?)`, seal).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("invalid aggregate reference or interval")
	}
	rows, err := db.QueryContext(ctx, "SELECT payload FROM rollups LIMIT ?", MaxRollupRows+1)
	if err != nil {
		return err
	}
	var n, size, population int64
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			break
		}
		var a *ProbeAggregate
		a, err = DecodeProbeAggregate(payload)
		if err != nil {
			break
		}
		if a.attempts+a.unknown == 0 {
			err = fmt.Errorf("empty stored aggregate")
			break
		}
		n++
		size += int64(len(payload))
		population += a.attempts + a.unknown
		if n > MaxRollupRows || size > MaxRollupStorageBytes {
			err = ErrCapacity
			break
		}
	}
	e := rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if e != nil {
		return e
	}
	if n != rowCount || size != byteCount || population > compacted {
		return fmt.Errorf("aggregate metadata disagrees with stored population")
	}
	if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM probe_live l LEFT JOIN streams s ON s.id=l.stream WHERE s.id IS NULL)`).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("orphan live history")
	}
	if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM streams s WHERE NOT EXISTS(SELECT 1 FROM probe_live l WHERE l.stream=s.id) AND (EXISTS(SELECT 1 FROM probes p WHERE p.stream=s.id AND p.ts>?) OR EXISTS(SELECT 1 FROM rollups r WHERE r.stream=s.id AND r.end_ts>?)))`, expired, expired).Scan(&invalid); err != nil {
		return err
	}
	if invalid != 0 {
		return fmt.Errorf("retained stream missing live history snapshot")
	}
	rows, err = db.QueryContext(ctx, `SELECT l.observed,l.payload,l.digest,s.node,s.peer,s.path,s.relay,s.uplink,s.source FROM probe_live l JOIN streams s ON s.id=l.stream LIMIT ?`, TieredMaxStreams+1)
	if err != nil {
		return err
	}
	n = 0
	for rows.Next() {
		var observed int64
		var payload, digest []byte
		var st Stream
		if err = rows.Scan(&observed, &payload, &digest, &st.NodeID, &st.PeerID, &st.Path, &st.RelayID, &st.Uplink, &st.Source); err != nil {
			break
		}
		if _, err = decodeLive(payload, digest, observed, st); err != nil {
			break
		}
		n++
		if n > TieredMaxStreams {
			err = ErrCapacity
			break
		}
	}
	e = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return e
}
