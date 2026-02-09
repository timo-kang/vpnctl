package metrics

import (
	"testing"
	"time"

	"vpnctl/internal/model"
)

func TestSummarize_Basic(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	items := []model.Metric{
		{Timestamp: now.Add(-10 * time.Second), RTTMs: 10, JitterMs: 1, LossPct: 0, ThroughputMbps: 5},
		{Timestamp: now.Add(-5 * time.Second), RTTMs: 20, JitterMs: 2, LossPct: 50, ThroughputMbps: 15},
	}
	s := Summarize(items, now.Add(-1*time.Minute))
	if s.Count != 2 {
		t.Fatalf("count=%d", s.Count)
	}
	if s.AvgRTTMs != 15 {
		t.Fatalf("avg_rtt=%.2f", s.AvgRTTMs)
	}
	if s.MinRTTMs != 10 || s.MaxRTTMs != 20 {
		t.Fatalf("min/max=%.2f/%.2f", s.MinRTTMs, s.MaxRTTMs)
	}
	if s.P95RTTMs != 20 {
		t.Fatalf("p95=%.2f", s.P95RTTMs)
	}
}

func TestPercentile_Edges(t *testing.T) {
	t.Parallel()

	values := []float64{1, 2, 3, 4}
	if got := percentile(values, 0); got != 1 {
		t.Fatalf("p0=%v", got)
	}
	if got := percentile(values, 1); got != 4 {
		t.Fatalf("p100=%v", got)
	}
}
