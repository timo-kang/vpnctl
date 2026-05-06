// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	NodesRegistered = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vpnctl_nodes_registered",
		Help: "Number of registered nodes",
	})

	NodesOnline = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vpnctl_nodes_online",
		Help: "Number of online nodes (seen within last 60s)",
	})

	DirectProbesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpnctl_direct_probes_total",
		Help: "Total direct probe attempts",
	}, []string{"node", "peer", "success"})

	P2PReadyPairs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vpnctl_p2p_ready_pairs",
		Help: "Number of peer pairs with P2P readiness confirmed",
	})

	// Node-side metrics (used by monitor)
	ProbeRTTSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vpnctl_probe_rtt_seconds",
		Help: "Last probe round-trip time in seconds",
	}, []string{"peer"})

	ProbeSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vpnctl_probe_success",
		Help: "Last probe success (1) or failure (0)",
	}, []string{"peer"})

	ProbeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpnctl_probe_total",
		Help: "Total probe attempts",
	}, []string{"peer", "result"})

	HealthFailures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vpnctl_health_failures",
		Help: "Current consecutive health check failures",
	})

	LinkQualityLevel = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vpnctl_link_quality",
		Help: "Link quality level (3=good, 2=degraded, 1=poor, 0=offline)",
	}, []string{"peer"})

	ProbeLossRatio = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vpnctl_probe_loss_ratio",
		Help: "Recent probe loss ratio (0.0 to 1.0)",
	}, []string{"peer"})
)
