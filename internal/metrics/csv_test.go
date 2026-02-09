package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/model"
)

func TestAppendCSV_WritesHeaderOnce(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "metrics.csv")

	m1 := model.Metric{Timestamp: time.Unix(1, 0).UTC(), NodeID: "n1", PeerID: "p1", Path: "relay"}
	m2 := model.Metric{Timestamp: time.Unix(2, 0).UTC(), NodeID: "n1", PeerID: "p2", Path: "relay"}

	if err := AppendCSV(path, []model.Metric{m1}); err != nil {
		t.Fatalf("AppendCSV #1: %v", err)
	}
	if err := AppendCSV(path, []model.Metric{m2}); err != nil {
		t.Fatalf("AppendCSV #2: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d\n%s", len(lines), string(data))
	}
	if !strings.HasPrefix(lines[0], "timestamp,") {
		t.Fatalf("missing header: %q", lines[0])
	}
}
