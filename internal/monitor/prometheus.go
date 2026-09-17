// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type qualityCollector struct {
	monitor *Monitor
	peers   map[string]*prometheus.Desc
	global  map[string]*prometheus.Desc
}

// Collector evaluates freshness at scrape time using the same snapshot as HTTP.
// Its series disappear when successful discovery removes a peer.
func (m *Monitor) Collector() prometheus.Collector {
	c := &qualityCollector{monitor: m, peers: map[string]*prometheus.Desc{}, global: map[string]*prometheus.Desc{}}
	for name, help := range map[string]string{
		"vpnctl_link_quality":                           "Windowed quality (-1=unknown, 0=offline, 1=poor, 2=degraded, 3=good)",
		"vpnctl_probe_loss_ratio":                       "Windowed failed probes divided by all probes; NaN when unmeasured",
		"vpnctl_quality_rtt_seconds":                    "Windowed mean of successful RTTs in seconds; NaN when unmeasured",
		"vpnctl_quality_sample_count":                   "Number of attempts in the published measurement window",
		"vpnctl_quality_stale":                          "One if the published observation cannot be treated as current",
		"vpnctl_quality_observed_timestamp_seconds":     "Last probe observation Unix timestamp; NaN when unmeasured",
		"vpnctl_quality_last_success_timestamp_seconds": "Last successful probe this process observed; NaN if none",
		"vpnctl_probe_rtt_seconds":                      "Latest successful probe RTT in seconds; NaN on failure or stale data",
		"vpnctl_probe_success":                          "Latest probe success (1) or failure (0); NaN if stale",
	} {
		c.peers[name] = prometheus.NewDesc(name, help, []string{"peer"}, nil)
	}
	for name, help := range map[string]string{
		"vpnctl_quality_window_seconds":      "Configured trailing measurement window in seconds",
		"vpnctl_quality_stale_after_seconds": "Configured maximum observation age in seconds",
		"vpnctl_monitor_collection_ok":       "One if discovery is current and successful (including an empty set)",
		"vpnctl_monitor_storage_ok":          "One if writes in the latest collection cycle succeeded",
	} {
		c.global[name] = prometheus.NewDesc(name, help, nil, nil)
	}
	return c
}

func (c *qualityCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.peers {
		ch <- desc
	}
	for _, desc := range c.global {
		ch <- desc
	}
}
func optional(v *float64, scale float64) float64 {
	if v == nil {
		return math.NaN()
	}
	return *v * scale
}
func timestamp(v *time.Time) float64 {
	if v == nil {
		return math.NaN()
	}
	return float64(v.UnixNano()) / 1e9
}
func truth(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
func (c *qualityCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.monitor.Latest()
	for name, value := range map[string]float64{
		"vpnctl_quality_window_seconds":      c.monitor.cfg.Quality.Window.Seconds(),
		"vpnctl_quality_stale_after_seconds": c.monitor.cfg.Quality.StaleAfter.Seconds(),
		"vpnctl_monitor_collection_ok":       truth(!snap.Stale && (snap.ErrorReason == "" || snap.ErrorReason == "no_peers")),
		"vpnctl_monitor_storage_ok":          truth(!snap.Time.IsZero() && snap.StorageError == ""),
	} {
		ch <- prometheus.MustNewConstMetric(c.global[name], prometheus.GaugeValue, value)
	}
	for _, p := range snap.Peers {
		q := p.Quality
		latestRTT, latestSuccess := math.NaN(), math.NaN()
		if !q.Stale && q.SampleCount > 0 {
			latestSuccess = truth(p.Success)
			if p.Success {
				latestRTT = float64(p.RTTus) / 1e6
			}
		}
		for name, value := range map[string]float64{
			"vpnctl_link_quality":                           float64(q.Level),
			"vpnctl_probe_loss_ratio":                       optional(q.LossPct, .01),
			"vpnctl_quality_rtt_seconds":                    optional(q.RTTMs, .001),
			"vpnctl_quality_sample_count":                   float64(q.SampleCount),
			"vpnctl_quality_stale":                          truth(q.Stale),
			"vpnctl_quality_observed_timestamp_seconds":     timestamp(q.ObservedAt),
			"vpnctl_quality_last_success_timestamp_seconds": timestamp(q.LastSuccessAt),
			"vpnctl_probe_rtt_seconds":                      latestRTT,
			"vpnctl_probe_success":                          latestSuccess,
		} {
			ch <- prometheus.MustNewConstMetric(c.peers[name], prometheus.GaugeValue, value, q.PeerIP)
		}
	}
}
