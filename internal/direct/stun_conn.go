package direct

import (
	"context"
	"net"
	"sync"

	"github.com/pion/stun/v3"
)

// stunConn demultiplexes datagrams without blocking Shared's reader on the
// library reader. A one-packet queue bounds duplicate-response memory usage.
type stunConn struct {
	shared      *Shared
	ctx         context.Context
	remote      *net.UDPAddr
	transaction [stun.TransactionIDSize]byte
	packets     chan []byte
	closed      chan struct{}
	once        sync.Once
}

func (c *stunConn) Read(buf []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.ctx.Done():
		// The library retries read errors. Wait for Close instead of spinning until
		// ProbeSTUN handles the cancellation and closes the client.
		<-c.closed
		return 0, net.ErrClosed
	case packet := <-c.packets:
		return copy(buf, packet), nil
	}
}

func (c *stunConn) Write(buf []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	return c.shared.write(c.ctx, buf, c.remote)
}

func (c *stunConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *stunConn) deliver(remote *net.UDPAddr, packet []byte) {
	if !sameUDPAddr(remote, c.remote) {
		return
	}
	msg := &stun.Message{Raw: packet}
	if msg.Decode() != nil || msg.TransactionID != c.transaction {
		return
	}
	if msg.Type != stun.BindingSuccess && msg.Type != stun.BindingError {
		return
	}
	select {
	case <-c.closed:
		return
	default:
	}
	select {
	case c.packets <- append([]byte(nil), packet...):
	default:
	}
}
