package stunutil

import (
	"context"
	"fmt"
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
		addr, err := probeServer(ctx, server, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		results = append(results, addr)
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

	client, err := stun.DialURI(uri, &stun.DialConfig{})
	if err != nil {
		return "", err
	}
	defer client.Close()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	result := make(chan stun.XORMappedAddress, 1)
	fail := make(chan error, 1)

	go func() {
		var addr stun.XORMappedAddress
		err := client.Do(msg, func(res stun.Event) {
			if res.Error != nil {
				fail <- res.Error
				return
			}
			if err := addr.GetFrom(res.Message); err != nil {
				fail <- err
				return
			}
			result <- addr
		})
		if err != nil {
			fail <- err
		}
	}()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	select {
	case addr := <-result:
		return addr.String(), nil
	case err := <-fail:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
