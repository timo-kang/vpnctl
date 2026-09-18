package controller

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"vpnctl/internal/history"
)

type alertCollector struct {
	server          *Server
	now             func() time.Time
	active, unknown *prometheus.Desc
}

func newAlertCollector(s *Server) *alertCollector {
	labels := []string{"code", "severity"}
	return &alertCollector{s, time.Now,
		prometheus.NewDesc("vpnctl_alert_active", "Number of registered nodes with an active observation alert", labels, nil),
		prometheus.NewDesc("vpnctl_alert_unknown", "Number of registered nodes without sufficient current evidence for an alert", labels, nil)}
}
func (c *alertCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.active; ch <- c.unknown }
func (c *alertCollector) Collect(ch chan<- prometheus.Metric) {
	active, unknown := map[string]float64{}, map[string]float64{}
	now := c.now()
	storage, ok := c.server.history.(history.EventStorage)
	for _, node := range c.server.fleetNodes() {
		var alerts []history.Alert
		var err error
		if ok {
			alerts, err = storage.Alerts(context.Background(), node.ID, now)
		}
		if !ok || err != nil {
			for _, code := range history.AlertCodes {
				unknown[code]++
			}
			continue
		}
		for _, a := range alerts {
			if !a.Known {
				unknown[a.Code]++
			} else if a.Active {
				active[a.Code]++
			}
		}
	}
	for _, code := range history.AlertCodes {
		ch <- prometheus.MustNewConstMetric(c.active, prometheus.GaugeValue, active[code], code, history.AlertSeverity(code))
		ch <- prometheus.MustNewConstMetric(c.unknown, prometheus.GaugeValue, unknown[code], code, history.AlertSeverity(code))
	}
}
func (s *Server) metricsHandler() http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(newAlertCollector(s))
	return promhttp.HandlerFor(prometheus.Gatherers{prometheus.DefaultGatherer, registry}, promhttp.HandlerOpts{})
}
