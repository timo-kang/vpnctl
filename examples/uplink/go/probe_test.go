// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type echoCounts struct {
	connections atomic.Int64
	mu          sync.Mutex
	requests    []string
}

func echoFixture(t *testing.T, wrong *atomic.Bool) (probeConfig, *echoCounts) {
	return echoFixtureHandler(t, func(line []byte) []byte {
		if wrong != nil && wrong.Load() {
			line = append([]byte(nil), line...)
			// Keep protocol and request ID valid; alter only the nonce.
			at := len(line) - 2
			if line[at] == '0' {
				line[at] = '1'
			} else {
				line[at] = '0'
			}
		}
		return line
	})
}
func echoFixtureHandler(t *testing.T, response func([]byte) []byte) (probeConfig, *echoCounts) {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	cert, config := certificate.Certificate(), certificate.TLS.Clone()
	certificate.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	counts := new(echoCounts)
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			counts.connections.Add(1)
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				r := bufio.NewReaderSize(c, 256)
				for {
					line, err := r.ReadSlice('\n')
					if err != nil {
						return
					}
					counts.mu.Lock()
					counts.requests = append(counts.requests, string(line))
					counts.mu.Unlock()
					line = response(line)
					if _, err = c.Write(line); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { cancel(); l.Close(); wg.Wait() })
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return probeConfig{Address: l.Addr().String(), ServerName: "example.com", Roots: roots, ConnectTimeout: time.Second, IOTimeout: 150 * time.Millisecond, Interval: 50 * time.Millisecond}, counts
}

func runUntil(t *testing.T, cfg probeConfig, goal func(probeSnapshot) bool) probeSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stats := newProbeStats()
	done := make(chan error, 1)
	go func() { done <- runProbe(ctx, cfg, stats) }()
	for !goal(stats.snapshot()) && ctx.Err() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("payload cancellation stalled")
	}
	result := stats.snapshot()
	if !goal(result) {
		t.Fatal("payload target not reached", result.Correct, result.Attempts, result.Ambiguous)
	}
	return result
}

func TestProbePreservesHealthyConnection(t *testing.T) {
	cfg, connections := echoFixture(t, nil)
	s := runUntil(t, cfg, func(s probeSnapshot) bool { return s.Correct >= 4 })
	if connections.connections.Load() != 1 || s.Connections != 1 || s.ExistingSocketCorrect < 3 || s.NewSocketCorrect != 1 {
		t.Fatal("healthy connection replaced")
	}
	if s.Ambiguous != 0 || s.MaxGapNS == 0 {
		t.Fatal("incorrect payload metrics")
	}
}
func TestProbeRejectsWrongNonceAndDoesNotReplay(t *testing.T) {
	var wrong atomic.Bool
	wrong.Store(true)
	cfg, counts := echoFixture(t, &wrong)
	var once sync.Once
	s := runUntil(t, cfg, func(s probeSnapshot) bool {
		if s.Ambiguous >= 1 {
			once.Do(func() { wrong.Store(false) })
		}
		return s.Correct >= 2
	})
	if s.InvalidResponses != 1 || s.Connections < 2 || s.NewSocketCorrect != 1 || s.ExistingSocketCorrect < 1 {
		t.Fatal("wrong response accepted or recovery unmeasured")
	}
	counts.mu.Lock()
	defer counts.mu.Unlock()
	seen := map[string]bool{}
	for i, wire := range counts.requests {
		fields := strings.Fields(wire)
		if len(fields) != 3 || fields[1] != strconv.Itoa(i+1) || seen[fields[2]] {
			t.Fatal("request ID or nonce replayed on actual wire")
		}
		seen[fields[2]] = true
	}
}
func TestProbeRejectsPreviousCorrectResponse(t *testing.T) {
	var mu sync.Mutex
	var first []byte
	cfg, _ := echoFixtureHandler(t, func(line []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		if first == nil {
			first = append([]byte(nil), line...)
		}
		return first
	})
	s := runUntil(t, cfg, func(s probeSnapshot) bool { return s.InvalidResponses >= 2 })
	if s.Correct != 1 || s.Ambiguous < 2 {
		t.Fatal("previous valid response accepted for new operation")
	}
}
func TestProbeRejectsUntrustedTLS(t *testing.T) {
	cfg, _ := echoFixture(t, nil)
	cfg.Roots = x509.NewCertPool()
	s := runUntil(t, cfg, func(s probeSnapshot) bool { return s.Attempts >= 2 })
	if s.Correct != 0 || s.Connections != 0 || s.Ambiguous != 0 {
		t.Fatal("untrusted TLS counted as application success")
	}
}
func TestTLSConnectCannotResetPayloadBackoff(t *testing.T) {
	var wrong atomic.Bool
	wrong.Store(true)
	cfg, _ := echoFixture(t, &wrong)
	s := runUntil(t, cfg, func(s probeSnapshot) bool { return s.Attempts >= 4 })
	if s.Correct != 0 || s.InvalidResponses < 4 || s.Connections < 4 {
		t.Fatal("incorrect response counted as success")
	}
	for i, e := range s.Events[:4] {
		upper := uint64(250*time.Millisecond) * uint64(1<<i)
		if e.NextDelayNS < upper/2 || e.NextDelayNS > upper {
			t.Fatal("TLS handshake reset application backoff", i, e.NextDelayNS)
		}
	}
}
func TestProbeEventStorageBound(t *testing.T) {
	s := newProbeStats()
	for i := 0; i < 5000; i++ {
		s.record(probeEvent{Request: uint64(i + 1), Failure: "connect"})
	}
	v := s.snapshot()
	if len(v.Events) != 4096 || v.DroppedEvents != 904 || v.Attempts != 5000 {
		t.Fatal("event storage unbounded or eviction hidden")
	}
}
