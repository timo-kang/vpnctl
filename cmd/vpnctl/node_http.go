// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"vpnctl/internal/metrics"
)

// startNodeMetricsHTTP exposes only probe-history delivery counters on IPv4
// loopback. Peer identity and other process metrics are intentionally omitted.
func startNodeMetricsHTTP(port int, cancel func()) (func(), string, error) {
	if port < 0 || port > 65535 {
		return nil, "", fmt.Errorf("node metrics port must be 0..65535")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, "", fmt.Errorf("node metrics bind on port %d: %w", port, err)
	}
	registry := prometheus.NewRegistry()
	if err := registry.Register(metrics.ProbeHistoryDeliveryTotal); err != nil {
		_ = listener.Close()
		return nil, "", fmt.Errorf("register node history metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	if cancel == nil {
		cancel = func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("node metrics server failed", "err", err)
			cancel()
		}
	}()
	var once sync.Once
	stop := func() { once.Do(func() { _ = server.Close(); <-done }) }
	return stop, listener.Addr().String(), nil
}
