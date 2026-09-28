// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package wgstats

import (
	"math"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricPeer struct {
	Node, Peer, Key string
	View            View
}
type collector struct {
	read func() []MetricPeer
	desc map[string]*prometheus.Desc
}

func Collector(read func() []MetricPeer) prometheus.Collector {
	c := &collector{read: read, desc: map[string]*prometheus.Desc{}}
	for name, help := range map[string]string{
		"rx_bytes":                   "Absolute received bytes (gauge, approximate above 2^53); NaN when unknown or stale",
		"tx_bytes":                   "Absolute transmitted bytes (gauge, approximate above 2^53); NaN when unknown or stale",
		"rx_bytes_per_second":        "Inferred receive rate; NaN without continuity evidence",
		"tx_bytes_per_second":        "Inferred transmit rate; NaN without continuity evidence",
		"handshake_age_seconds":      "Age of observed handshake; NaN for never, clock skew, unknown or stale",
		"observed_timestamp_seconds": "Kernel collection timestamp",
		"collection_valid":           "One for current successful kernel collection",
		"endpoint_available":         "One for a usable endpoint; NaN when unknown or stale",
		"stale":                      "One when collection is stale",
	} {
		c.desc[name] = prometheus.NewDesc("vpnctl_wireguard_"+name, help, []string{"node", "peer", "public_key"}, nil)
	}
	return c
}
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.desc {
		ch <- d
	}
}
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	optional := func(f *float64) float64 {
		if f == nil {
			return math.NaN()
		}
		return *f
	}
	for _, p := range c.read() {
		v := p.View
		rx, tx, ep, valid, stale := math.NaN(), math.NaN(), math.NaN(), float64(0), float64(0)
		if v.Stale {
			stale = 1
		}
		if !v.Stale && v.Validity == "observed" {
			valid = 1
			ep = 0
			if v.Endpoint {
				ep = 1
			}
			if v.RX != nil {
				rx = float64(*v.RX)
			}
			if v.TX != nil {
				tx = float64(*v.TX)
			}
		}
		for n, f := range map[string]float64{"rx_bytes": rx, "tx_bytes": tx, "rx_bytes_per_second": optional(v.RXPerSecond), "tx_bytes_per_second": optional(v.TXPerSecond), "handshake_age_seconds": optional(v.HandshakeAgeSeconds), "observed_timestamp_seconds": float64(v.ObservedAt.UnixMicro()) / 1e6, "collection_valid": valid, "endpoint_available": ep, "stale": stale} {
			ch <- prometheus.MustNewConstMetric(c.desc[n], prometheus.GaugeValue, f, p.Node, p.Peer, p.Key)
		}
	}
}
