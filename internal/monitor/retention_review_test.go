package monitor

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRetentionConcurrentWithProbeWrites(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "monitor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<10001) INSERT INTO probes SELECT ?,'old','10.0.0.1',0,0 FROM n`, time.Now().Add(-48*time.Hour).UnixMicro())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if e := s.InsertContext(ctx, ProbeResult{Timestamp: time.Now(), PeerKey: "current", PeerIP: "10.0.0.2", Success: true}); e != nil {
					t.Error(e)
					return
				}
			}
		}()
	}
	removed, err := s.CleanupContext(ctx, 24*time.Hour)
	wg.Wait()
	if err != nil || removed != 10001 {
		t.Fatal(removed, err)
	}
	rows, err := s.QueryAll(72 * time.Hour)
	if err != nil || len(rows) != 400 {
		t.Fatal("concurrent writes lost", len(rows), err)
	}
	cancel()
	if _, err = s.CleanupContext(ctx, 24*time.Hour); err == nil {
		t.Fatal("cancelled cleanup succeeded")
	}
}
