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

	// Cumulative node-side measurements; live gauges are collected from Monitor.
	ProbeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpnctl_probe_total",
		Help: "Total probe attempts",
	}, []string{"peer", "result"})

	HealthFailures = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vpnctl_health_failures",
		Help: "Current consecutive health check failures",
	})

	EventTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vpnctl_events_total",
		Help: "Accepted state and diagnostic events by fixed kind and severity",
	}, []string{"kind", "severity", "result"})

	AlertActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vpnctl_alert_active",
		Help: "Current event-derived alert state by fixed alert code and severity",
	}, []string{"code", "severity"})
)

var (
	PKIEventsTotal   = promauto.NewCounterVec(prometheus.CounterOpts{Name: "vpnctl_pki_events_total", Help: "PKI operations by component, operation and result"}, []string{"component", "operation", "result"})
	PKIExpirySeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "vpnctl_pki_expiry_seconds", Help: "Seconds until the current server, earliest trusted CA, or local client expires"}, []string{"kind"})
	PKICertificates  = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "vpnctl_pki_certificates", Help: "Tracked client certificates by current status"}, []string{"status"})
	PKIOverlap       = promauto.NewGauge(prometheus.GaugeOpts{Name: "vpnctl_pki_ca_overlap", Help: "One while a staged CA transition is in progress"})
)

var SystemCommandSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "vpnctl_system_command_seconds",
	Help:    "System command duration including startup and wait; command labels are ip, wg or other",
	Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
}, []string{"command", "result"})

// Only fixed operation/stage names are used; never node IDs, paths or secrets.
var ControllerStageSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "vpnctl_controller_stage_seconds",
	Help:    "Controller handler, admission, registry wait, authorization and transaction duration",
	Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10, 30},
}, []string{"operation", "stage"})
