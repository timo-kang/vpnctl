//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// net.Pipe does not touch host interfaces, routes or firewall state. The peer
// stops at each protocol boundary so a timeout must identify the actual stage.
func TestM3TCPProbeDiagnostics(t *testing.T) {
	for _, stage := range []string{"connect", "write_nonce", "read_source", "read_nonce", "parse_source", "verify_nonce", "complete"} {
		t.Run(stage, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			tracked := &m3DeadlineConn{Conn: client}
			done := make(chan struct{})
			peerDone := make(chan struct{})
			defer func() { close(done); <-peerDone }()
			go func() {
				defer close(peerDone)
				if stage == "connect" || stage == "write_nonce" {
					<-done
					return
				}
				b := make([]byte, 16)
				if _, err := io.ReadFull(server, b); err != nil {
					return
				}
				if stage == "read_source" {
					<-done
					return
				}
				if stage == "parse_source" {
					server.Write([]byte("invalid-address\n"))
					return
				}
				if _, err := server.Write([]byte("198.18.0.12:1234\n")); err != nil {
					return
				}
				if stage == "read_nonce" {
					<-done
					return
				}
				if stage == "verify_nonce" {
					b[0] ^= 1
				}
				server.Write(b)
			}()
			before := time.Now()
			r, err := measureM3TCPProbe(func(timeout time.Duration) (net.Conn, error) {
				if timeout != time.Second {
					t.Fatalf("connect deadline changed: %s", timeout)
				}
				if stage == "connect" {
					return nil, os.ErrDeadlineExceeded
				}
				return tracked, nil
			})
			protocolError := stage == "parse_source" || stage == "verify_nonce"
			if (err != nil) != protocolError || r.TCP == nil || r.TCP.Phase != stage {
				t.Fatalf("missing stage evidence: %+v %v", r, err)
			}
			trace := r.TCP
			if trace.StartedAt.Before(before) || trace.PhaseStartedAt.Before(trace.StartedAt) || trace.FinishedAt.Before(trace.PhaseStartedAt) || trace.FinishedAt.After(time.Now()) || r.MS < trace.PhaseMS || trace.PhaseMS < 0 {
				t.Fatalf("invalid timing evidence: %+v duration=%f", trace, r.MS)
			}
			if (trace.ConnectedAt == nil) != (stage == "connect") {
				t.Fatalf("incorrect connection evidence: %+v", trace)
			}
			if trace.ConnectedAt != nil && (tracked.calls != 1 || !tracked.deadline.Equal(trace.ConnectedAt.Add(time.Second))) {
				t.Fatal("single shared 1s exchange deadline changed")
			}
			if stage == "complete" {
				if !r.OK || r.Failure != "" || r.Source != "198.18.0.12" {
					t.Fatalf("echo not verified: %+v", r)
				}
			} else if protocolError {
				if r.OK || r.Failure != "" || r.Source != "" {
					t.Fatal("protocol error hidden as network outage", r)
				}
			} else if r.OK || r.Failure != "timeout" || r.Source != "" {
				t.Fatalf("timeout became success: %+v", r)
			}
			b, err := json.Marshal(r)
			if err != nil || bytes.Contains(b, []byte("i/o timeout")) {
				t.Fatal("diagnostics must use classified errors only")
			}
		})
	}
}

type m3DeadlineConn struct {
	net.Conn
	deadline time.Time
	calls    int
}

func (c *m3DeadlineConn) SetDeadline(at time.Time) error {
	c.deadline, c.calls = at, c.calls+1
	return c.Conn.SetDeadline(at)
}

func TestM3TCPProbeConnectClassification(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{syscall.ENETUNREACH, "unreachable"}, {syscall.EHOSTUNREACH, "unreachable"},
		{syscall.ENODEV, "interface_unavailable"}, {syscall.EADDRNOTAVAIL, "interface_unavailable"},
		{syscall.ECONNREFUSED, "refused"}, {io.EOF, ""},
	} {
		r, err := measureM3TCPProbe(func(time.Duration) (net.Conn, error) { return nil, test.err })
		if r.OK || r.Failure != test.want || (err != nil) != (test.want == "") || r.TCP == nil || r.TCP.Phase != "connect" || r.TCP.ConnectedAt != nil {
			t.Fatalf("classification changed: %+v error=%v", r, err)
		}
	}
}
