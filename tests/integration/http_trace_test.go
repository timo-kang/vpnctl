//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// Milestones are measured from probe start, not added together. Missing fields
// distinguish a request that never reached a phase from a phase taking 0ms.
type httpMilestones struct {
	Attempts       int      `json:"attempts"`
	ConnectStartMS *float64 `json:"connect_start_ms,omitempty"`
	ConnectDoneMS  *float64 `json:"connect_done_ms,omitempty"`
	GetConnMS      *float64 `json:"get_conn_ms,omitempty"`
	ConnectedMS    *float64 `json:"connected_ms,omitempty"`
	TLSStartMS     *float64 `json:"tls_start_ms,omitempty"`
	TLSDoneMS      *float64 `json:"tls_done_ms,omitempty"`
	WroteMS        *float64 `json:"wrote_request_ms,omitempty"`
	FirstByteMS    *float64 `json:"first_byte_ms,omitempty"`
	Reused         bool     `json:"reused"`
}

type httpProbeTrace struct {
	mu         sync.Mutex
	milestones httpMilestones
}

func tracedProbe(ctx context.Context, start time.Time) (context.Context, *httpProbeTrace) {
	trace := &httpProbeTrace{}
	mark := func(target **float64) {
		value := float64(time.Since(start)) / float64(time.Millisecond)
		*target = &value
	}
	hooks := &httptrace.ClientTrace{
		GetConn: func(string) {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			trace.milestones.Attempts++
			mark(&trace.milestones.GetConnMS)
		},
		ConnectStart: func(_, _ string) { trace.mu.Lock(); defer trace.mu.Unlock(); mark(&trace.milestones.ConnectStartMS) },
		ConnectDone: func(_, _ string, err error) {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			if err == nil {
				mark(&trace.milestones.ConnectDoneMS)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			mark(&trace.milestones.ConnectedMS)
			trace.milestones.Reused = info.Reused
		},
		TLSHandshakeStart: func() { trace.mu.Lock(); defer trace.mu.Unlock(); mark(&trace.milestones.TLSStartMS) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			if err == nil {
				mark(&trace.milestones.TLSDoneMS)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			if info.Err == nil {
				mark(&trace.milestones.WroteMS)
			}
		},
		GotFirstResponseByte: func() { trace.mu.Lock(); defer trace.mu.Unlock(); mark(&trace.milestones.FirstByteMS) },
	}
	return httptrace.WithClientTrace(ctx, hooks), trace
}
func (t *httpProbeTrace) snapshot() *httpMilestones {
	t.mu.Lock()
	defer t.mu.Unlock()
	copy := t.milestones
	return &copy
}
