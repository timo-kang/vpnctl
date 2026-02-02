package metrics

import (
	"math"
	"sort"
	"time"

	"vpnctl/internal/model"
)

// Summary is a basic statistics snapshot.
type Summary struct {
	Count             int
	From              time.Time
	To                time.Time
	AvgRTTMs          float64
	P95RTTMs          float64
	MinRTTMs          float64
	MaxRTTMs          float64
	AvgJitterMs       float64
	AvgLossPct        float64
	AvgThroughputMbps float64
}

// Summarize computes summary metrics for items in a time window.
func Summarize(items []model.Metric, since time.Time) Summary {
	filtered := make([]model.Metric, 0, len(items))
	for _, m := range items {
		if m.Timestamp.After(since) || m.Timestamp.Equal(since) {
			filtered = append(filtered, m)
		}
	}

	if len(filtered) == 0 {
		return Summary{Count: 0}
	}

	values := make([]float64, 0, len(filtered))
	var sumRTT, sumJitter, sumLoss, sumThroughput float64
	minRTT := math.MaxFloat64
	maxRTT := 0.0
	from := filtered[0].Timestamp
	to := filtered[0].Timestamp

	for _, m := range filtered {
		values = append(values, m.RTTMs)
		sumRTT += m.RTTMs
		sumJitter += m.JitterMs
		sumLoss += m.LossPct
		sumThroughput += m.ThroughputMbps
		if m.RTTMs < minRTT {
			minRTT = m.RTTMs
		}
		if m.RTTMs > maxRTT {
			maxRTT = m.RTTMs
		}
		if m.Timestamp.Before(from) {
			from = m.Timestamp
		}
		if m.Timestamp.After(to) {
			to = m.Timestamp
		}
	}

	sort.Float64s(values)
	p95 := percentile(values, 0.95)
	count := float64(len(filtered))

	return Summary{
		Count:             len(filtered),
		From:              from,
		To:                to,
		AvgRTTMs:          sumRTT / count,
		P95RTTMs:          p95,
		MinRTTMs:          minRTT,
		MaxRTTMs:          maxRTT,
		AvgJitterMs:       sumJitter / count,
		AvgLossPct:        sumLoss / count,
		AvgThroughputMbps: sumThroughput / count,
	}
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	if p <= 0 {
		return values[0]
	}
	if p >= 1 {
		return values[len(values)-1]
	}
	idx := int(math.Ceil(p*float64(len(values)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}
