package direct

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	resp := &Responder{conn: conn}
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
	return r.conn.Close()
}

func (r *Responder) serve() {
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
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return 0, err
	}
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return 0, err
	}

	// DialUDP "connects" the socket so the kernel filters out packets from other sources.
	// This avoids brittle string comparisons on source addresses (IPv4-mapped IPv6, etc).
	conn, err := net.DialUDP("udp", udpAddr, peerUDP)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
	}

	nonce, err := randomNonce(8)
	if err != nil {
		return 0, err
	}
	payload := []byte(probePrefix + nonce)

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return 0, err
	}

	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}

	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, err
		}
		msg := string(buf[:n])
		if msg == ackPrefix+nonce {
			return time.Since(start), nil
		}
		if ctx != nil {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
			}
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

	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return 0, 0, err
	}
	peerUDP, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return 0, 0, err
	}

	conn, err := net.DialUDP("udp", udpAddr, peerUDP)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
	}

	payload := make([]byte, packetSize)
	copy(payload, []byte(echoPrefix))

	start := time.Now()
	for i := 0; i < count; i++ {
		copy(payload[len(echoPrefix):], fmt.Sprintf("%08d", i))
		if _, err := conn.Write(payload); err != nil {
			return 0, 0, err
		}
	}

	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}

	received := 0
	receivedBytes := 0
	buf := make([]byte, packetSize+64)
	for received < count {
		n, err := conn.Read(buf)
		if err != nil {
			break
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
