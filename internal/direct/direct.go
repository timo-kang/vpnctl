// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package direct

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	probePrefix = "vpnctl-direct-probe:"
	ackPrefix   = "vpnctl-direct-ack:"
	echoPrefix  = "vpnctl-echo:"
)

// Responder listens for direct probes and replies with acks.
type Responder struct {
	conn *net.UDPConn
	done chan struct{}
}

// StartResponder starts a UDP responder on the given address (e.g. ":0").
func StartResponder(addr string) (*Responder, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	resp := &Responder{conn: conn, done: make(chan struct{})}
	go resp.serve()
	return resp, nil
}

// LocalAddr returns the local address of the responder.
func (r *Responder) LocalAddr() string {
	if r == nil || r.conn == nil {
		return ""
	}
	return r.conn.LocalAddr().String()
}

// Close stops the responder.
func (r *Responder) Close() error {
	if r == nil || r.conn == nil {
		return nil
	}
	err := r.conn.Close()
	<-r.done
	return err
}

func (r *Responder) serve() {
	defer close(r.done)
	buf := make([]byte, 2048)
	for {
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		handlePacket(r.conn, addr, buf[:n])
	}
}

func handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	msg := string(data)
	if strings.HasPrefix(msg, probePrefix) {
		nonce := strings.TrimPrefix(msg, probePrefix)
		payload := []byte(ackPrefix + nonce)
		_, _ = conn.WriteToUDP(payload, addr)
		return
	}
	if strings.HasPrefix(msg, echoPrefix) {
		_, _ = conn.WriteToUDP(data, addr)
	}
}

// ProbePeer sends a direct probe to a peer and waits for an ack.
func ProbePeer(ctx context.Context, localAddr, peerAddr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := probeContext(ctx, timeout)
	defer cancel()
	conn, cleanup, err := dialProbe(ctx, localAddr, peerAddr)
	if err != nil {
		return 0, contextError(ctx, err)
	}
	defer cleanup()

	nonce, err := randomNonce(8)
	if err != nil {
		return 0, contextError(ctx, err)
	}
	payload := []byte(probePrefix + nonce)

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, contextError(ctx, err)
	}

	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, contextError(ctx, err)
		}
		msg := string(buf[:n])
		if msg == ackPrefix+nonce {
			if err := contextError(ctx, nil); err != nil {
				return 0, err
			}
			return time.Since(start), nil
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
}

// PerfProbe sends echo packets and estimates throughput and loss.
func PerfProbe(ctx context.Context, localAddr, peerAddr string, packetSize, count int, timeout time.Duration) (float64, float64, error) {
	if count <= 0 {
		return 0, 0, fmt.Errorf("count must be > 0")
	}
	if packetSize < len(echoPrefix)+8 {
		packetSize = len(echoPrefix) + 8
	}

	parent := ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := probeContext(parent, timeout)
	defer cancel()
	conn, cleanup, err := dialProbe(ctx, localAddr, peerAddr)
	if err != nil {
		return 0, 0, err
	}
	defer cleanup()

	payload := make([]byte, packetSize)
	copy(payload, []byte(echoPrefix))

	start := time.Now()
	for i := 0; i < count; i++ {
		copy(payload[len(echoPrefix):], fmt.Sprintf("%08d", i))
		if _, err := conn.Write(payload); err != nil {
			return 0, 0, contextError(ctx, err)
		}
	}

	received := 0
	receivedBytes := 0
	buf := make([]byte, packetSize+64)
	for received < count {
		n, err := conn.Read(buf)
		if err != nil {
			if parentErr := contextError(parent, nil); parentErr != nil {
				return 0, 0, parentErr
			}
			var netErr net.Error
			if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
				break
			}
			return 0, 0, err
		}
		if n <= 0 {
			continue
		}
		if !strings.HasPrefix(string(buf[:n]), echoPrefix) {
			continue
		}
		received++
		receivedBytes += n
	}

	if err := contextError(parent, nil); err != nil {
		return 0, 0, err
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}

	lossPct := 100.0 * float64(count-received) / float64(count)
	throughputMbps := (float64(receivedBytes) * 8.0 / elapsed.Seconds()) / 1_000_000.0
	return throughputMbps, lossPct, nil
}

func randomNonce(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
