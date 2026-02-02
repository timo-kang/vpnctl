package metrics

import (
	"encoding/csv"
	"io"
	"strconv"
	"time"

	"vpnctl/internal/model"
)

// WriteCSV writes metrics to CSV with a fixed column order.
func WriteCSV(w io.Writer, items []model.Metric) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
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
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, m := range items {
		record := []string{
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
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return writer.Error()
}

