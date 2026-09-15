// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package direct

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

type peerProbe struct {
	remote *net.UDPAddr
	ack    chan struct{}
}

// Shared uses a single UDP socket for STUN and direct probes.
type Shared struct {
	conn       *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	writeToken chan struct{}
	mu         sync.Mutex
	stunConn   *stunConn
	pending    map[string]*peerProbe
}

// ListenShared creates a shared UDP socket and starts the read loop.
func ListenShared(addr string) (*Shared, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	shared := &Shared{conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{}), writeToken: make(chan struct{}, 1)}
	shared.writeToken <- struct{}{}
	go shared.readLoop()
	return shared, nil
}

func (s *Shared) LocalAddr() string {
	if s == nil || s.conn == nil {
		return ""
	}
	return s.conn.LocalAddr().String()
}

// Close interrupts pending requests, including DNS lookups, and joins the reader.
func (s *Shared) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	s.cancel()
	err := s.conn.Close()
	<-s.done
	return err
}

func (s *Shared) requestContext(parent context.Context, timeout time.Duration) (context.Context, func()) {
	ctx, cancel := probeContext(parent, timeout)
	stop := context.AfterFunc(s.ctx, cancel)
	if s.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (s *Shared) requestError(ctx context.Context, err error) error {
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	return contextError(ctx, err)
}

// Writes share a socket deadline. Serialize deadline changes and join a running
// cancellation callback before another writer can acquire the socket.
func (s *Shared) write(ctx context.Context, payload []byte, remote *net.UDPAddr) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-s.writeToken:
	}
	defer func() { s.writeToken <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadline, _ := ctx.Deadline()
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.conn.SetWriteDeadline(time.Now()); close(interrupted) })
	n, err := s.conn.WriteToUDP(payload, remote)
	if !stop() {
		<-interrupted
	}
	return n, contextError(ctx, err)
}

// ProbeSTUN preserves the STUN client's retransmission and transaction handling.
// The adapter owns only its queue; closing it never closes the shared UDP socket.
func (s *Shared) ProbeSTUN(parent context.Context, server string, timeout time.Duration) (result string, err error) {
	if s == nil || s.conn == nil {
		return "", fmt.Errorf("shared socket not initialized")
	}
	ctx, cancel := s.requestContext(parent, timeout)
	defer cancel()
	defer func() { err = s.requestError(ctx, err) }()
	server = strings.TrimPrefix(strings.TrimSpace(server), "stun:")
	if server == "" {
		return "", fmt.Errorf("empty STUN server")
	}
	remote, err := resolveUDPAddr(ctx, server)
	if err != nil {
		return "", err
	}
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	adapter := &stunConn{shared: s, ctx: ctx, remote: remote, transaction: msg.TransactionID, packets: make(chan []byte, 1), closed: make(chan struct{})}
	s.mu.Lock()
	if s.stunConn != nil {
		s.mu.Unlock()
		return "", fmt.Errorf("stun probe already in progress")
	}
	s.stunConn = adapter
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.stunConn = nil; s.mu.Unlock() }()
	client, err := stun.NewClient(adapter)
	if err != nil {
		adapter.Close()
		return "", err
	}
	defer client.Close()
	type response struct {
		address string
		err     error
	}
	done := make(chan response, 1)
	if err := client.Start(msg, func(event stun.Event) {
		res := response{err: event.Error}
		if res.err == nil && event.Message.Type != stun.BindingSuccess {
			res.err = fmt.Errorf("STUN binding error response")
		}
		if res.err == nil {
			var mapped stun.XORMappedAddress
			res.err = mapped.GetFrom(event.Message)
			if res.err == nil {
				res.address = mapped.String()
			}
		}
		// A shutdown/error callback must never wait for a caller that has returned.
		select {
		case done <- res:
		default:
		}
	}); err != nil {
		return "", err
	}
	select {
	case res := <-done:
		return res.address, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (s *Shared) readLoop() {
	defer close(s.done)
	defer s.cancel()
	defer s.conn.Close()
	buf := make([]byte, 2048)
	for {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if stun.IsMessage(buf[:n]) {
			s.mu.Lock()
			adapter := s.stunConn
			s.mu.Unlock()
			if adapter != nil {
				adapter.deliver(remote, buf[:n])
			}
			continue
		}
		msg := string(buf[:n])
		if strings.HasPrefix(msg, ackPrefix) {
			nonce := strings.TrimPrefix(msg, ackPrefix)
			s.mu.Lock()
			pending := s.pending[nonce]
			if pending != nil && sameUDPAddr(remote, pending.remote) {
				delete(s.pending, nonce)
				close(pending.ack)
			}
			s.mu.Unlock()
			continue
		}
		// Responder writes also use the serialized deadline so another probe's
		// cancellation cannot accidentally poison subsequent replies.
		var reply []byte
		if strings.HasPrefix(msg, probePrefix) {
			reply = []byte(ackPrefix + strings.TrimPrefix(msg, probePrefix))
		}
		if strings.HasPrefix(msg, echoPrefix) {
			reply = buf[:n]
		}
		if reply != nil {
			ctx, cancel := s.requestContext(s.ctx, 100*time.Millisecond)
			_, _ = s.write(ctx, reply, remote)
			cancel()
		}
	}
}

func (s *Shared) ProbePeer(parent context.Context, peerAddr string, timeout time.Duration) (rtt time.Duration, err error) {
	if s == nil || s.conn == nil {
		return 0, fmt.Errorf("shared socket not initialized")
	}
	ctx, cancel := s.requestContext(parent, timeout)
	defer cancel()
	defer func() { err = s.requestError(ctx, err) }()
	remote, err := resolveUDPAddr(ctx, peerAddr)
	if err != nil {
		return 0, err
	}
	nonce, err := randomNonce(8)
	if err != nil {
		return 0, err
	}
	pending := &peerProbe{remote: remote, ack: make(chan struct{})}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[string]*peerProbe)
	}
	s.pending[nonce] = pending
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, nonce); s.mu.Unlock() }()
	start := time.Now()
	if _, err := s.write(ctx, []byte(probePrefix+nonce), remote); err != nil {
		return 0, err
	}
	select {
	case <-pending.ack:
		return time.Since(start), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
