// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package stunutil

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v3"
)

const (
	NATTypeUnknown          = "unknown"
	NATTypeSymmetric        = "symmetric"
	NATTypeConeOrRestricted = "cone_or_restricted"
)

// Probe queries STUN servers for a public mapped address.
// Note: The mapped address is for the STUN socket and may not match other sockets.
func Probe(ctx context.Context, servers []string, timeout time.Duration) (string, string, error) {
	if len(servers) == 0 {
		return "", NATTypeUnknown, fmt.Errorf("no STUN servers provided")
	}

	results := make([]string, 0, len(servers))
	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return "", NATTypeUnknown, err
		}
		addr, err := probeServer(ctx, server, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		results = append(results, addr)
	}

	if err := ctx.Err(); err != nil {
		return "", NATTypeUnknown, err
	}

	if len(results) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("STUN probe failed")
		}
		return "", NATTypeUnknown, lastErr
	}

	natType := Classify(results)
	return results[0], natType, nil
}

// Classify infers NAT type by comparing mapped addresses from multiple servers.
func Classify(addrs []string) string {
	if len(addrs) < 2 {
		return NATTypeUnknown
	}
	first := addrs[0]
	symmetric := false
	for _, addr := range addrs[1:] {
		if addr != first {
			symmetric = true
			break
		}
	}
	if symmetric {
		return NATTypeSymmetric
	}
	return NATTypeConeOrRestricted
}

func probeServer(ctx context.Context, server string, timeout time.Duration) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	uriStr := strings.TrimSpace(server)
	if uriStr == "" {
		return "", fmt.Errorf("empty STUN server")
	}
	if !strings.HasPrefix(uriStr, "stun:") {
		uriStr = "stun:" + uriStr
	}
	uri, err := stun.ParseURI(uriStr)
	if err != nil {
		return "", err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port)))
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return "", err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, err := stun.NewClient(conn)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer client.Close()
	type response struct {
		addr string
		err  error
	}
	done := make(chan response, 1)
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if err := client.Start(msg, func(event stun.Event) {
		res := response{err: event.Error}
		if res.err == nil && event.Message.Type != stun.BindingSuccess {
			res.err = fmt.Errorf("STUN binding error response")
		}
		if res.err == nil {
			var mapped stun.XORMappedAddress
			res.err = mapped.GetFrom(event.Message)
			if res.err == nil {
				res.addr = mapped.String()
			}
		}
		select {
		case done <- res:
		default:
		}
	}); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	select {
	case res := <-done:
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return res.addr, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
