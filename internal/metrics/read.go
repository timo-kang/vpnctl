package metrics

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"vpnctl/internal/model"
)

// ReadCSV loads metrics from a CSV file.
func ReadCSV(path string) ([]model.Metric, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return readCSV(file)
}

func readCSV(r io.Reader) ([]model.Metric, error) {
	reader := csv.NewReader(r)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	start := 0
	if len(records[0]) > 0 && records[0][0] == "timestamp" {
		start = 1
	}

	items := make([]model.Metric, 0, len(records)-start)
	for i := start; i < len(records); i++ {
		rec := records[i]
		if len(rec) < 12 {
			return nil, fmt.Errorf("invalid record at line %d", i+1)
		}
		ts, err := time.Parse(time.RFC3339Nano, rec[0])
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp at line %d: %w", i+1, err)
		}
		rtt, _ := strconv.ParseFloat(rec[4], 64)
		jitter, _ := strconv.ParseFloat(rec[5], 64)
		loss, _ := strconv.ParseFloat(rec[6], 64)
		throughput, _ := strconv.ParseFloat(rec[7], 64)
		mtu, _ := strconv.Atoi(rec[8])
		items = append(items, model.Metric{
			Timestamp:      ts,
			NodeID:         rec[1],
			PeerID:         rec[2],
			Path:           rec[3],
			RTTMs:          rtt,
			JitterMs:       jitter,
			LossPct:        loss,
			ThroughputMbps: throughput,
			MTU:            mtu,
			NATType:        rec[9],
			PublicAddr:     rec[10],
			RelayReason:    rec[11],
		})
	}

	return items, nil
}
