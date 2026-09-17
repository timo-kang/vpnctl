package controller

import (
	"net/http"
	"time"
	"vpnctl/internal/metrics"
)

func observeStage(operation, stage string, start time.Time) {
	metrics.ControllerStageSeconds.WithLabelValues(operation, stage).Observe(time.Since(start).Seconds())
}

func observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fixed route allowlist avoids unbounded labels from arbitrary request paths.
		operation := "other"
		switch r.URL.Path {
		case "/register", "/candidates", "/metrics", "/nat-probe", "/direct-result", "/wg-config", "/bootstrap", "/pki/trust", "/pki/renew", "/pki/ack", "/fleet/status", "/fleet/history":
			operation = r.URL.Path
		case "/prom/metrics":
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		defer observeStage(operation, "handler", start)
		next.ServeHTTP(w, r)
	})
}
