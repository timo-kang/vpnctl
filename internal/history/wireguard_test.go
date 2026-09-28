package history

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vpnctl/internal/wgstats"
)

func wgBinding(n int) wgstats.Binding {
	var key [32]byte
	key[0] = byte(n)
	key[1] = byte(n >> 8)
	return wgstats.Binding{NodeID: fmt.Sprintf("node-%d", n), PublicKey: base64.StdEncoding.EncodeToString(key[:]), VPNIP: fmt.Sprintf("10.7.%d.%d", n/254, n%254+1), Epoch: "00000000000000000000000000000001"}
}
func wgReport(at time.Time, n int, rx uint64) wgstats.Report {
	value := wgstats.Counter(rx)
	return wgstats.Report{ID: wgstats.ID(), ObservedAt: at, Reporter: wgBinding(n), Interface: "wg0", Peers: []wgstats.Reading{{Peer: wgBinding(n + 1), Sample: wgstats.Sample{ObservedAt: at, Generation: "00000000000000000000000000000002", Validity: "observed", RX: &value, TX: &value, Handshake: pointer(at.Add(-time.Second)), Endpoint: true}}}}
}
func putWG(t *testing.T, s *Store, r wgstats.Report, now time.Time) {
	t.Helper()
	if e := s.IngestWireGuard(context.Background(), r, now); e != nil {
		t.Fatal(e)
	}
}
func TestWireGuardRestartBackupAndAllSchemaCombinations(t *testing.T) {
	for _, base := range []int{5, 6, 7, 8, 9} {
		t.Run(fmt.Sprint(base), func(t *testing.T) {
			s, now := newStore(t)
			ctx := context.Background()
			if base >= 6 {
				if e := s.EnableTiering(ctx, now); e != nil {
					t.Fatal(e)
				}
			}
			if base == 7 || base == 9 {
				if e := s.EnableReclamation(ctx); e != nil {
					t.Fatal(e)
				}
			}
			if base >= 8 {
				if e := s.EnableJitter(ctx); e != nil {
					t.Fatal(e)
				}
			}
			first := wgReport(now.Add(-time.Minute), 0, 1<<53+1)
			second := wgReport(now, 0, 1<<53+61)
			putWG(t, s, first, now)
			putWG(t, s, second, now)
			putWG(t, s, second, now)
			bad := second.Clone()
			bad.Peers[0].Sample.RX = pointer(wgstats.Counter(9))
			if e := s.IngestWireGuard(ctx, bad, now); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			late := first.Clone()
			late.ID = wgstats.ID()
			if e := s.IngestWireGuard(ctx, late, now); !errors.Is(e, ErrConflict) {
				t.Fatal(e)
			}
			before := s.LatestWireGuard(now)
			v := before["node-0"].Views[0]
			if v.RXPerSecond == nil || *v.RXPerSecond != 1 || *v.RXDelta != 60 {
				t.Fatal(v)
			}
			q, e := s.QueryWireGuard(ctx, "node-0", now, time.Hour, 1)
			if e != nil || !q.Truncated || len(q.Snapshots) != 1 || q.Storage.Rows != 2 || *q.Snapshots[0].Views[0].RXPerSecond != 1 {
				t.Fatal(q, e)
			}
			info, e := Inspect(ctx, s.path)
			if e != nil || info.SchemaVersion != base+10 {
				t.Fatal(info, e)
			}
			backup := filepath.Join(t.TempDir(), "backup.db")
			if e = Backup(ctx, s.path, backup); e != nil {
				t.Fatal(e)
			}
			restored := filepath.Join(t.TempDir(), "restored.db")
			if e = Restore(ctx, backup, restored, now); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(restored, now)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, reopened.LatestWireGuard(now)) {
				t.Fatal("restart changed view")
			}
			// Returned reports and views never alias the published counters.
			*before["node-0"].Views[0].RX = 0
			if *s.LatestWireGuard(now)["node-0"].Views[0].RX == 0 {
				t.Fatal("aliased view")
			}
			if e = s.Maintain(ctx, now.Add(wgstats.Retention)); e != nil {
				t.Fatal(e)
			}
			q, e = s.QueryWireGuard(ctx, "node-0", now.Add(wgstats.Retention), time.Hour, 10)
			if e != nil || q.Storage.Rows != 0 || q.Storage.Expired != 2 {
				t.Fatal(q, e)
			}
			if e = Check(ctx, s.path); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestWireGuardFeatureMigrationsAfterIngest(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	putWG(t, s, wgReport(now, 0, 1), now)
	for i, migrate := range []func() error{func() error { return s.EnableTiering(ctx, now) }, func() error { return s.EnableJitter(ctx) }, func() error { return s.EnableReclamation(ctx) }} {
		if e := migrate(); e != nil {
			t.Fatal(e)
		}
		want := []int{16, 18, 19}[i]
		info, e := Inspect(ctx, s.path)
		if e != nil || info.SchemaVersion != want {
			t.Fatal(info, e)
		}
		if e = Check(ctx, s.path); e != nil {
			t.Fatal(e)
		}
	}
}
func TestWireGuardRetentionQuotaCancellationAndRecovery(t *testing.T) {
	s, now := newStore(t)
	ctx := context.Background()
	start := now.Add(-23 * time.Hour)
	// Seed valid retained data in one transaction. Only the capacity boundary
	// needs public ingests; replaying 10,080 fsyncs/count scans obscures the risk.
	putWG(t, s, wgReport(start, 0, 0), now)
	seed, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := seed.Begin()
	if e != nil {
		t.Fatal(e)
	}
	stmt, e := tx.Prepare("INSERT INTO wireguard_reports VALUES(?,?,?,?,?)")
	if e != nil {
		t.Fatal(e)
	}
	var buffer bytes.Buffer
	z, e := gzip.NewWriterLevel(&buffer, gzip.NoCompression)
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i < MaxNodeWireGuardRows; i++ {
		r := wgReport(start.Add(time.Duration(i)*time.Second), 0, uint64(i))
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		buffer.Reset()
		z.Reset(&buffer)
		if _, e = z.Write(raw); e != nil {
			t.Fatal(e)
		}
		if e = z.Close(); e != nil {
			t.Fatal(e)
		}
		if _, e = stmt.Exec(r.Reporter.NodeID, r.ID, r.ObservedAt.UnixMicro(), buffer.Bytes(), sum[:]); e != nil {
			t.Fatal(e)
		}
	}
	stmt.Close()
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	seed.Close()
	s, e = Open(s.path, now)
	if e != nil {
		t.Fatal(e)
	}
	for i := MaxNodeWireGuardRows; i < MaxNodeWireGuardRows+3; i++ {
		putWG(t, s, wgReport(start.Add(time.Duration(i)*time.Second), 0, uint64(i)), now)
	}

	q, e := s.QueryWireGuard(ctx, "node-0", now, wgstats.Retention, 3)
	if e != nil || q.Storage.Rows != MaxNodeWireGuardRows || q.Storage.Evicted != 3 || q.Storage.LossStart == nil || !q.Storage.LossStart.Equal(start) || !q.Storage.LossEnd.Equal(start.Add(2*time.Second)) {
		t.Fatal(q.Storage, e)
	}
	if e = Check(ctx, s.path); e != nil {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before := s.LatestWireGuard(now)
	if e = s.IngestWireGuard(canceled, wgReport(now, 0, 9000), now); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, s.LatestWireGuard(now)) {
		t.Fatal("canceled write published")
	}
	// SQLite writer failure must not publish, followed by successful recovery.
	db, e := connect(s.path, false)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("CREATE TRIGGER wg_fail BEFORE INSERT ON wireguard_reports BEGIN SELECT RAISE(ABORT,'injected'); END"); e != nil {
		t.Fatal(e)
	}
	next := wgReport(now, 0, 9000)
	if e = s.IngestWireGuard(ctx, next, now); e == nil {
		t.Fatal("injected failure accepted")
	}
	if !reflect.DeepEqual(before, s.LatestWireGuard(now)) {
		t.Fatal("failed write published")
	}
	if _, e = db.Exec("DROP TRIGGER wg_fail"); e != nil {
		t.Fatal(e)
	}
	putWG(t, s, next, now)
	if e = Check(ctx, s.path); e != nil {
		t.Fatal(e)
	}
}
func TestWireGuardVariableMesh(t *testing.T) {
	for _, size := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, now := newStore(t)
			for cycle := 0; cycle < 3; cycle++ {
				for node := 0; node < size; node++ {
					r := wgReport(now.Add(time.Duration(cycle-2)*time.Minute), node, uint64(cycle*1000))
					r.Peers = nil
					for peer := 0; peer < size; peer++ {
						if peer == node {
							continue
						}
						reading := wgReport(r.ObservedAt, 0, uint64(cycle*1000)).Peers[0]
						reading.Peer = wgBinding(peer)
						r.Peers = append(r.Peers, reading)
					}
					putWG(t, s, r, now)
				}
			}
			got := s.LatestWireGuard(now)
			if len(got) != size {
				t.Fatal(len(got))
			}
			for _, r := range got {
				if len(r.Views) != size-1 {
					t.Fatal(len(r.Views))
				}
				for _, v := range r.Views {
					if v.RXDelta == nil || *v.RXDelta != 1000 {
						t.Fatal(v)
					}
				}
			}
			if e := Check(context.Background(), s.path); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestWireGuardLargeHistoryResponseIsExplicitlyTruncated(t *testing.T) {
	s, now := newStore(t)
	for i := 0; i < 24; i++ {
		r := wgReport(now.Add(time.Duration(i-24)*time.Minute), 0, uint64(i))
		r.Peers = nil
		for p := 1; p <= wgstats.MaxPeers; p++ {
			v := wgReport(r.ObservedAt, 0, uint64(i)).Peers[0]
			v.Peer = wgBinding(p)
			v.Sample.Generation = wgstats.ID()
			r.Peers = append(r.Peers, v)
		}
		putWG(t, s, r, now)
	}
	q, e := s.QueryWireGuard(context.Background(), "node-0", now, time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(q)
	if e != nil || len(b) > 5<<20 || !q.Truncated || len(q.Snapshots) == 0 || len(q.Snapshots) >= 24 || q.Storage.Rows != 24 {
		t.Fatal("unbounded or silently incomplete result", len(b), len(q.Snapshots), q.Truncated, e)
	}
	t.Logf("max-size peer reports=24 returned=%d response_bytes=%d", len(q.Snapshots), len(b))
}
