// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type probeConfig struct {
	Address, ServerName                 string
	Roots                               *x509.CertPool
	ConnectTimeout, IOTimeout, Interval time.Duration
}

type probeEvent struct {
	Request     uint64  `json:"request"`
	Connection  uint64  `json:"connection"`
	StartedNS   uint64  `json:"started_boot_ns,string"`
	ConnectedNS *string `json:"authenticated_connect_boot_ns"`
	FinishedNS  uint64  `json:"finished_boot_ns,string"`
	NextDelayNS uint64  `json:"next_delay_ns,string"`
	Reused      bool    `json:"existing_socket"`
	Correct     bool    `json:"correct"`
	Ambiguous   bool    `json:"outcome_unknown"`
	Failure     string  `json:"failure,omitempty"`
}
type probeSnapshot struct {
	Attempts              uint64       `json:"attempts"`
	Connections           uint64       `json:"authenticated_connections"`
	Correct               uint64       `json:"correct"`
	NewSocketCorrect      uint64       `json:"new_socket_correct"`
	ExistingSocketCorrect uint64       `json:"existing_socket_correct"`
	Ambiguous             uint64       `json:"outcome_unknown"`
	InvalidResponses      uint64       `json:"invalid_responses"`
	FirstCorrectNS        uint64       `json:"first_correct_boot_ns,string"`
	LastCorrectNS         uint64       `json:"last_correct_boot_ns,string"`
	MaxGapNS              uint64       `json:"max_correct_gap_ns,string"`
	DroppedEvents         uint64       `json:"dropped_events"`
	Events                []probeEvent `json:"events"`
}
type probeStats struct {
	mu    sync.Mutex
	value probeSnapshot
	next  int
}

func newProbeStats() *probeStats { return &probeStats{} }
func (s *probeStats) record(e probeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := &s.value
	v.Attempts++
	if e.ConnectedNS != nil {
		v.Connections++
	}
	if e.Ambiguous {
		v.Ambiguous++
	}
	if e.Failure == "unexpected_response" {
		v.InvalidResponses++
	}
	if e.Correct {
		v.Correct++
		if e.Reused {
			v.ExistingSocketCorrect++
		} else {
			v.NewSocketCorrect++
		}
		if v.FirstCorrectNS == 0 {
			v.FirstCorrectNS = e.FinishedNS
		}
		if v.LastCorrectNS > 0 && e.FinishedNS >= v.LastCorrectNS {
			v.MaxGapNS = max(v.MaxGapNS, e.FinishedNS-v.LastCorrectNS)
		}
		v.LastCorrectNS = e.FinishedNS
	}
	if len(v.Events) < 4096 {
		v.Events = append(v.Events, e)
	} else {
		v.Events[s.next] = e
		s.next = (s.next + 1) % 4096
		v.DroppedEvents++
	}
}
func (s *probeStats) snapshot() probeSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.value
	v.Events = append([]probeEvent(nil), s.value.Events[s.next:]...)
	v.Events = append(v.Events, s.value.Events[:s.next]...)
	return v
}
func bootNS() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0
	}
	return uint64(ts.Nano())
}
func probeWait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// runProbe sends only read-only echo operations. Every attempt has a new nonce
// and request ID. An incomplete response is outcome-unknown; this is NOT a retry
// template for business operations without an explicit idempotency contract.
// No API status is accepted here, so observations cannot close a healthy socket
// or reset payload backoff. The application owns its I/O deadlines.
func runProbe(ctx context.Context, cfg probeConfig, stats *probeStats) error {
	if stats == nil || cfg.Roots == nil || cfg.Address == "" || cfg.ServerName == "" || cfg.ConnectTimeout <= 0 || cfg.ConnectTimeout > 30*time.Second || cfg.IOTimeout <= 0 || cfg.IOTimeout > 30*time.Second || cfg.Interval < 50*time.Millisecond || cfg.Interval > 10*time.Second {
		return errors.New("invalid read-only probe configuration")
	}
	if address, err := netip.ParseAddrPort(cfg.Address); err != nil || address.Port() == 0 {
		return errors.New("literal IP and nonzero port required")
	}
	tlsConfig := &tls.Config{RootCAs: cfg.Roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS13}
	var conn *tls.Conn
	var reader *bufio.Reader
	var stop func() bool
	closeConn := func() {
		if stop != nil {
			stop()
			stop = nil
		}
		if conn != nil {
			conn.Close()
			conn = nil
			reader = nil
		}
	}
	defer closeConn()
	var request, connection uint64
	var retry time.Duration
	for ctx.Err() == nil {
		request++
		e := probeEvent{Request: request, StartedNS: bootNS(), Reused: conn != nil}
		if conn == nil {
			dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
			c, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsConfig}).DialContext(dialCtx, "tcp", cfg.Address)
			cancel()
			if err != nil {
				e.Failure = "connect"
			} else {
				conn = c.(*tls.Conn)
				connection++
				at := strconv.FormatUint(bootNS(), 10)
				e.ConnectedNS = &at
				reader = bufio.NewReaderSize(conn, 256)
				stop = context.AfterFunc(ctx, func() { c.Close() })
			}
		}
		if conn != nil {
			e.Connection = connection
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return errors.New("probe nonce unavailable")
			}
			wire := fmt.Sprintf("VPNCTL-ECHO/1 %d %s\n", request, hex.EncodeToString(nonce[:]))
			conn.SetWriteDeadline(time.Now().Add(cfg.IOTimeout))
			// Even a write error may follow a partial request reaching the server.
			e.Ambiguous = true
			if _, err := io.WriteString(conn, wire); err != nil {
				e.Failure = "write"
			} else {
				conn.SetReadDeadline(time.Now().Add(cfg.IOTimeout))
				line, err := reader.ReadSlice('\n')
				if err != nil {
					e.Failure = "read"
				} else if string(line) != wire {
					e.Failure = "unexpected_response"
				} else {
					e.Correct = true
					e.Ambiguous = false
				}
			}
		}
		e.FinishedNS = bootNS()
		delay := cfg.Interval
		if e.Correct {
			retry = 0 // TLS connect, API events, and writes alone never reset this.
		} else {
			closeConn()
			if retry == 0 {
				retry = 250 * time.Millisecond
			} else {
				retry = min(8*time.Second, retry*2)
			}
			delay = retry/2 + time.Duration(mathrand.Int64N(int64(retry/2)+1))
		}
		e.NextDelayNS = uint64(delay)
		stats.record(e)
		if err := probeWait(ctx, delay); err != nil {
			return err
		}
	}
	return ctx.Err()
}
