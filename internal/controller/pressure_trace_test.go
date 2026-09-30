// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptrace"
	"sync"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/labreport"
)

type pressureHTTPEvent struct {
	Kind     string  `json:"kind"`
	OffsetMS float64 `json:"offset_ms"`
	Reused   bool    `json:"reused,omitempty"`
	Failed   bool    `json:"failed,omitempty"`
}
type pressureControlAttempt struct {
	Phase         string              `json:"phase"`
	Operation     string              `json:"operation"`
	Result        string              `json:"result"`
	DurationMS    float64             `json:"duration_ms"`
	HTTP          []pressureHTTPEvent `json:"http_events"`
	OmittedEvents int                 `json:"omitted_events"`
}
type pressureTrace struct {
	mu      sync.Mutex
	closed  bool
	events  []pressureHTTPEvent
	omitted int
}

// Fixed event names and relative time only: never retain callback addresses,
// certificates, request data, URLs or raw error messages in public artifacts.
func tracePressureRequest(ctx context.Context, started time.Time) (context.Context, *pressureTrace) {
	r := &pressureTrace{events: []pressureHTTPEvent{}}
	add := func(kind string, reused, failed bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closed {
			return
		}
		if len(r.events) >= 32 {
			r.omitted++
			return
		}
		r.events = append(r.events, pressureHTTPEvent{kind, float64(time.Since(started).Microseconds()) / 1000, reused, failed})
	}
	trace := &httptrace.ClientTrace{
		GetConn:              func(string) { add("get_conn", false, false) },
		GotConn:              func(i httptrace.GotConnInfo) { add("got_conn", i.Reused, false) },
		ConnectStart:         func(string, string) { add("connect_start", false, false) },
		ConnectDone:          func(_, _ string, err error) { add("connect_done", false, err != nil) },
		TLSHandshakeStart:    func() { add("tls_start", false, false) },
		TLSHandshakeDone:     func(_ tls.ConnectionState, err error) { add("tls_done", false, err != nil) },
		WroteRequest:         func(i httptrace.WroteRequestInfo) { add("request_written", false, i.Err != nil) },
		GotFirstResponseByte: func() { add("first_response_byte", false, false) },
	}
	return httptrace.WithClientTrace(ctx, trace), r
}
func (r *pressureTrace) finish(phase, operation string, elapsed time.Duration, err error, canceled bool) pressureControlAttempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true // Ignore callbacks that arrive after a canceled call returns.
	result := "success"
	var httpErr *api.HTTPError
	switch {
	case canceled || errors.Is(err, context.Canceled):
		result = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		result = "deadline_exceeded"
	case errors.As(err, &httpErr):
		result = fmt.Sprintf("http_%d", httpErr.StatusCode)
	case err != nil:
		result = "error"
	case elapsed > 2*time.Second:
		result = "budget_exceeded"
	}
	return pressureControlAttempt{phase, operation, result, float64(elapsed.Microseconds()) / 1000, append([]pressureHTTPEvent{}, r.events...), r.omitted}
}
func (ev *pressureEvidence) recordControl(values map[string][]float64, a pressureControlAttempt) {
	// Keep failure evidence even if earlier successful calls exhausted the cap.
	if len(ev.ControlAttempts) < 2048 {
		ev.ControlAttempts = append(ev.ControlAttempts, a)
	} else {
		ev.OmittedControlAttempts++
		if a.Result != "success" {
			ev.ControlAttempts[len(ev.ControlAttempts)-1] = a
		}
	}
	if a.Result != "success" {
		return
	}
	values[a.Operation] = append(values[a.Operation], a.DurationMS)
	if ev.Control == nil {
		ev.Control = map[string]map[string]labreport.Distribution{}
	}
	if ev.Control[a.Phase] == nil {
		ev.Control[a.Phase] = map[string]labreport.Distribution{}
	}
	// Publish every completed sample; a later t.Fatal must not discard it.
	ev.Control[a.Phase][a.Operation] = labreport.Summarize(values[a.Operation])
}
