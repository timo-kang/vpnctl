package metrics

import (
	"encoding/csv"
	"io"
	"os"
	"strconv"
	"time"

	"vpnctl/internal/model"
)

// WriteCSV writes metrics to CSV with a fixed column order.
func WriteCSV(w io.Writer, items []model.Metric) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headerRow()); err != nil {
		return err
	}

	for _, m := range items {
		if err := writer.Write(recordRow(m)); err != nil {
			return err
		}
	}

	return writer.Error()
}

// AppendCSV appends metrics to a CSV file, creating it with a header if needed.
func AppendCSV(path string, items []model.Metric) error {
	if len(items) == 0 {
		return nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if info.Size() == 0 {
		if err := writer.Write(headerRow()); err != nil {
			return err
		}
	}

	for _, m := range items {
		if err := writer.Write(recordRow(m)); err != nil {
			return err
		}
	}

	return writer.Error()
}

func headerRow() []string {
	return []string{
		"timestamp",
		"node_id",
		"peer_id",
		"path",
		"rtt_ms",
		"jitter_ms",
		"loss_pct",
		"throughput_mbps",
		"mtu",
		"nat_type",
		"public_addr",
		"relay_reason",
	}
}

func recordRow(m model.Metric) []string {
	return []string{
		m.Timestamp.UTC().Format(time.RFC3339Nano),
		m.NodeID,
		m.PeerID,
		m.Path,
		strconv.FormatFloat(m.RTTMs, 'f', 3, 64),
		strconv.FormatFloat(m.JitterMs, 'f', 3, 64),
		strconv.FormatFloat(m.LossPct, 'f', 3, 64),
		strconv.FormatFloat(m.ThroughputMbps, 'f', 3, 64),
		strconv.Itoa(m.MTU),
		m.NATType,
		m.PublicAddr,
		m.RelayReason,
	}
}
