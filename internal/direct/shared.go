package direct

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// Shared uses a single UDP socket for STUN and direct probes.
type Shared struct {
	conn       *net.UDPConn
	mu         sync.Mutex
	stunWriter io.Writer
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

	shared := &Shared{conn: conn}
	go shared.readLoop()
	return shared, nil
}

// LocalAddr returns the local address for the shared socket.
func (s *Shared) LocalAddr() string {
	if s == nil || s.conn == nil {
		return ""
	}
	return s.conn.LocalAddr().String()
}

// Close closes the shared socket.
func (s *Shared) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// ProbeSTUN sends a STUN binding request using the shared socket.
func (s *Shared) ProbeSTUN(ctx context.Context, server string, timeout time.Duration) (string, error) {
	if s == nil || s.conn == nil {
		return "", fmt.Errorf("shared socket not initialized")
	}

	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("empty STUN server")
	}
	if strings.HasPrefix(server, "stun:") {
		server = strings.TrimPrefix(server, "stun:")
	}

	stunAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return "", err
	}

	stunL, stunR := net.Pipe()
	client, err := stun.NewClient(stunR, stun.WithNoConnClose())
	if err != nil {
		_ = stunL.Close()
		_ = stunR.Close()
		return "", err
	}
	defer func() {
		_ = client.Close()
		_ = stunL.Close()
		_ = stunR.Close()
	}()

	s.mu.Lock()
	if s.stunWriter != nil {
		s.mu.Unlock()
		return "", fmt.Errorf("stun probe already in progress")
	}
	s.stunWriter = stunL
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.stunWriter = nil
		s.mu.Unlock()
	}()

	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := stunL.Read(buf)
			if err != nil {
				writeErr <- err
				return
			}
			if _, err := s.conn.WriteToUDP(buf[:n], stunAddr); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	var xorAddr stun.XORMappedAddress
	done := make(chan error, 1)
	go func() {
		done <- client.Do(msg, func(res stun.Event) {
			if res.Error != nil {
				return
			}
			_ = xorAddr.GetFrom(res.Message)
		})
	}()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	select {
	case err := <-done:
		if err != nil {
			return "", err
		}
		if xorAddr.IP == nil {
			return "", fmt.Errorf("stun response missing mapped address")
		}
		return xorAddr.String(), nil
	case err := <-writeErr:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (s *Shared) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if stun.IsMessage(buf[:n]) {
			s.mu.Lock()
			w := s.stunWriter
			s.mu.Unlock()
			if w != nil {
				_, _ = w.Write(buf[:n])
			}
			continue
		}

		handlePacket(s.conn, addr, buf[:n])
	}
}
