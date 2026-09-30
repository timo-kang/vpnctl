// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

func TestPressureEvidencePreservesDeadlineAndPriorSamples(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := srv.Client()
	defer client.CloseIdleConnections()
	ev := pressureEvidence{}
	values := map[string][]float64{}
	for _, path := range []string{"/ok", "/stall"} {
		budget := 2 * time.Second
		if path == "/stall" {
			budget = 100 * time.Millisecond
		}
		ctx, stop := context.WithTimeout(context.Background(), budget)
		started := time.Now()
		ctx, trace := tracePressureRequest(ctx, started)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path+"?secret=do-not-publish", nil)
		req.Header.Set("Authorization", "do-not-publish")
		res, err := client.Do(req)
		if res != nil {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
		elapsed := time.Since(started)
		stop()
		ev.recordControl(values, trace.finish("baseline", "renew_install_ack", elapsed, err, false))
	}
	if len(ev.ControlAttempts) != 2 || ev.ControlAttempts[0].Result != "success" || ev.ControlAttempts[1].Result != "deadline_exceeded" || len(values["renew_install_ack"]) != 1 || ev.Control["baseline"]["renew_install_ack"].Count != 1 {
		t.Fatal("failed call or prior success evidence lost")
	}
	failed := ev.ControlAttempts[1]
	if failed.DurationMS < 90 || len(failed.HTTP) == 0 {
		t.Fatal("missing failure timing")
	}
	b, err := json.Marshal(ev)
	if err != nil || strings.Contains(string(b), "do-not-publish") || strings.Contains(string(b), srv.URL) || strings.Contains(string(b), "/stall") {
		t.Fatal("unsafe pressure artifact")
	}
}

func TestPressureTraceBoundsAndLateCallbacks(t *testing.T) {
	ctx, trace := tracePressureRequest(context.Background(), time.Now())
	hooks := httptrace.ContextClientTrace(ctx)
	for i := 0; i < 40; i++ {
		hooks.GetConn("private-address")
	}
	a := trace.finish("baseline", "test", time.Millisecond, nil, false)
	hooks.GetConn("late-private-address")
	if len(a.HTTP) != 32 || a.OmittedEvents != 8 || len(trace.events) != 32 || trace.omitted != 8 {
		t.Fatal("unbounded or late trace")
	}
	ev := pressureEvidence{ControlAttempts: make([]pressureControlAttempt, 2048)}
	a.Result = "deadline_exceeded"
	ev.recordControl(map[string][]float64{}, a)
	if len(ev.ControlAttempts) != 2048 || ev.ControlAttempts[2047].Result != "deadline_exceeded" || ev.OmittedControlAttempts != 1 {
		t.Fatal("failure lost at evidence capacity")
	}
}
