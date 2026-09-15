package direct

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// The budget includes name resolution and writes, not only the reply wait.
// A nonpositive timeout retains the caller's deadline/cancellation semantics.
func probeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}

func resolveUDPAddr(ctx context.Context, address string) (*net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, "udp", service)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone(), Port: port}, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host}
	}
	chosen := ips[0]
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			chosen = ip
			break
		}
	}
	return &net.UDPAddr{IP: chosen.IP, Zone: chosen.Zone, Port: port}, nil
}

func dialProbe(ctx context.Context, local, remote string) (*net.UDPConn, func(), error) {
	localAddr, err := resolveUDPAddr(ctx, local)
	if err != nil {
		return nil, nil, err
	}
	remoteAddr, err := resolveUDPAddr(ctx, remote)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return conn, func() { stop(); conn.Close() }, nil
}

func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A socket deadline may fire just before the context timer is scheduled.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}
