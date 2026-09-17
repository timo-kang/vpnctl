// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/execx"
)

type NetworkProber struct{ Runner execx.ContextRunner }

func (p NetworkProber) route(ctx context.Context, ip net.IP, iface string, port int, protocol, mark string) Route {
	r := p.Runner
	if r == nil {
		r = &execx.OSRunner{}
	}
	protocolNumber := "6"
	if protocol == "udp" {
		protocolNumber = "17"
	}
	args := []string{"-j", "route", "get", ip.String(), "ipproto", protocolNumber, "dport", strconv.Itoa(port)}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	if iface != "" {
		args = append(args, "oif", iface)
	}
	out, err := r.OutputContext(ctx, "ip", args...)
	if err != nil {
		if strings.Contains(err.Error(), "Network is unreachable") || strings.Contains(err.Error(), "No route to host") {
			return Route{Check: Down("no_route")}
		}
		return Route{Check: Unknown("route_unavailable")}
	}
	var rows []struct {
		Dev     string `json:"dev"`
		Prefsrc string `json:"prefsrc"`
		Src     string `json:"src"`
		Gateway string `json:"gateway"`
		Type    string `json:"type"`
	}
	if json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 {
		return Route{Check: Unknown("route_output_invalid")}
	}
	v := rows[0]
	if v.Type == "unreachable" || v.Type == "blackhole" || v.Type == "prohibit" {
		return Route{Check: Down("no_route")}
	}
	if v.Prefsrc == "" {
		v.Prefsrc = v.Src
	}
	if !validInterface(v.Dev) || iface != "" && v.Dev != iface {
		return Route{Check: Down("unexpected_interface")}
	}
	return Route{Check: Up(), Interface: v.Dev, Source: v.Prefsrc, Gateway: v.Gateway, Destination: ip.String()}
}

// Probe resolves once and dials that same IP. The route is a kernel lookup at
// probe time, not proof of WireGuard peer selection or a different app's marks.
// An explicit interface binds BOTH lookup and socket; failure to bind is unknown.
func (p NetworkProber) Probe(ctx context.Context, e Endpoint, iface string) (Route, Check) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	route := Route{Check: Unknown("not_observed")}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, e.Host)
	if err != nil || len(ips) == 0 {
		return route, Down("dns_failed")
	}
	limit := len(ips)
	if limit > 4 {
		limit = 4
	}
	result := Unknown("not_observed")
	for i := 0; i < limit; i++ {
		deadline, _ := ctx.Deadline()
		budget := time.Until(deadline) / time.Duration(limit-i)
		attempt, stop := context.WithTimeout(ctx, budget)
		r, c := p.probeIP(attempt, e, iface, ips[i].IP)
		stop()
		if c.State == "up" {
			return r, c
		}
		// Keep evidence of the furthest reachable stage if another address lacks a route.
		if route.State != "up" || r.State == "up" {
			route, result = r, c
		}
	}
	if len(ips) > limit {
		return route, Unknown("address_limit")
	}
	return route, result
}
func (p NetworkProber) probeIP(ctx context.Context, e Endpoint, iface string, ip net.IP) (Route, Check) {
	route := Route{Check: Unknown("not_observed")}
	var err error

	protocol := "tcp"
	if e.Protocol == "udp-echo" {
		protocol = "udp"
	}
	route = p.route(ctx, ip, iface, e.Port, protocol, "")
	if route.State == "down" {
		return route, Down("route_blocked")
	}
	dialer := net.Dialer{}
	if iface != "" {
		dialer.Control = func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			err := c.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			})
			if err != nil {
				return err
			}
			return bindErr
		}
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, protocol, net.JoinHostPort(ip.String(), strconv.Itoa(e.Port)))
	if err != nil {
		return route, probeError(err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return route, Unknown("local_socket_error")
		}
	}
	if e.Protocol == "tls" {
		tlsConfig := &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
		if e.CAFile != "" {
			roots, err := readRoots(e.CAFile)
			if err != nil {
				return route, Unknown("trust_unavailable")
			}
			tlsConfig.RootCAs = roots
		}
		secured := tls.Client(conn, tlsConfig)
		if err = secured.HandshakeContext(ctx); err != nil {
			if ctx.Err() != nil {
				return route, Down("reachability_timeout")
			}
			return route, Down("tls_handshake_failed")
		}
	}
	if e.Protocol == "udp-echo" {
		payload := []byte("vpnctl-echo:" + rand.Text())
		buf := make([]byte, len(payload)+1)
		if _, err = conn.Write(payload); err == nil {
			var n int
			n, err = conn.Read(buf)
			if err == nil && !bytes.Equal(buf[:n], payload) {
				err = io.ErrUnexpectedEOF
			}
		}
		if err != nil {
			return route, probeError(err)
		}
	}
	rtt := float64(time.Since(start)) / float64(time.Millisecond)
	return route, Check{State: "up", RTTMs: &rtt}
}
func probeError(err error) Check {
	switch {
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES):
		return Unknown("probe_permission_denied")
	case errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENODEV):
		return Unknown("local_interface_unavailable")
	case errors.Is(err, syscall.ECONNREFUSED):
		return Down("service_refused")
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return Down("network_unreachable")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return Down("echo_mismatch")
	case errors.Is(err, context.Canceled):
		return Unknown("canceled")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Down("reachability_timeout")
	}
	return Unknown("probe_error")
}

// Transport reports the kernel-selected outer route for the selected WG peer.
// Read-only WG access may require CAP_NET_ADMIN; inability to inspect is unknown.
func (p NetworkProber) Transport(ctx context.Context, overlay Route) (Route, string) {
	unknown := Route{Check: Unknown("transport_unavailable")}
	if overlay.State != "up" || overlay.Interface == "" {
		return unknown, ""
	}
	destination, err := netip.ParseAddr(overlay.Destination)
	if err != nil {
		return unknown, ""
	}
	r := p.Runner
	if r == nil {
		r = &execx.OSRunner{}
	}
	allowed, err := r.OutputContext(ctx, "wg", "show", overlay.Interface, "allowed-ips")
	if err != nil {
		return unknown, ""
	}
	selected, bits := "", -1
	for _, line := range strings.Split(allowed, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, text := range fields[1:] {
			for _, value := range strings.Split(text, ",") {
				prefix, e := netip.ParsePrefix(value)
				if e == nil && prefix.Contains(destination) && prefix.Bits() > bits {
					selected, bits = fields[0], prefix.Bits()
				}
			}
		}
	}
	if selected == "" {
		return Route{Check: Down("no_wireguard_peer")}, ""
	}
	fingerprint := sha256.Sum256([]byte(selected))
	peerID := hex.EncodeToString(fingerprint[:])
	endpoints, err := r.OutputContext(ctx, "wg", "show", overlay.Interface, "endpoints")
	if err != nil {
		return unknown, peerID
	}
	endpoint := ""
	for _, line := range strings.Split(endpoints, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == selected {
			endpoint = fields[1]
			break
		}
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return Route{Check: Unknown("relay_endpoint_unavailable")}, peerID
	}
	ip := net.ParseIP(host)
	port, e := strconv.Atoi(portText)
	if ip == nil || e != nil || port < 1 || port > 65535 {
		return unknown, peerID
	}
	mark, err := r.OutputContext(ctx, "wg", "show", overlay.Interface, "fwmark")
	if err != nil {
		return unknown, peerID
	}
	if mark == "off" {
		mark = ""
	} else {
		v, e := strconv.ParseUint(mark, 0, 32)
		if e != nil {
			return unknown, peerID
		}
		mark = fmt.Sprint(v)
	}
	route := p.route(ctx, ip, "", port, "udp", mark)
	if route.Interface == overlay.Interface {
		route.Check = Down("recursive_tunnel_route")
	}
	return route, peerID
}

func readRoots(path string) (*x509.CertPool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("invalid CA file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("CA file too large")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	return roots, nil
}
