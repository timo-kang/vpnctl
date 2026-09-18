package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"vpnctl/internal/monitor"
)

// Binding is synchronous so an occupied metrics port cannot leave a seemingly
// healthy monitor running without its requested observation endpoints.
func startMonitorHTTP(mon *monitor.Monitor, port int, cancel func()) (func(), error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("monitor metrics bind on port %d: %w", port, err)
	}
	mux := http.NewServeMux()
	registry := prometheus.NewRegistry()
	registry.MustRegister(mon.Collector())
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.Gatherers{prometheus.DefaultGatherer, registry}, promhttp.HandlerOpts{}))
	mux.HandleFunc("/network/quality", mon.QualityHandler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("monitor metrics server failed", "err", err)
			cancel()
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { _ = server.Close(); <-done }) }, nil
}
