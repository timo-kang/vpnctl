// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

func echoEndpoint() string {
	host := os.Getenv("VPNCTL_UPLINK_ADDR")
	if host == "" {
		host = "10.77.0.1"
	}
	return net.JoinHostPort(host, "9191")
}

// Fragmentation is an explicit fixture profile, not a recommendation for
// production UDP or a claim that default PMTU discovery never loses a datagram.
func allowUDPFragmentation(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
	}); err != nil {
		return err
	}
	return optionErr
}

type echoObservation struct {
	Kind, Source string
	At           time.Time
}

// Record only the first source per protocol. This proves routed source
// preservation and SNAT on the actual target without logging packet contents.
func echoObserver() (func(string, net.Addr) error, func(), error) {
	path := os.Getenv("VPNCTL_ECHO_OBSERVATIONS")
	if path == "" {
		return func(string, net.Addr) error { return nil }, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	encoder := json.NewEncoder(f)
	return func(kind string, addr net.Addr) error {
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		key := kind + "/" + host
		if seen[key] {
			return nil
		}
		if err := encoder.Encode(echoObservation{kind, host, time.Now()}); err != nil {
			return err
		}
		seen[key] = true
		return nil
	}, func() { _ = f.Close() }, nil
}

type relayProbeResult struct {
	Kind        string    `json:"kind"`
	At          time.Time `json:"at"`
	FailureKind string    `json:"failure_kind,omitempty"`
	Size        int       `json:"payload_bytes"`
	OK          bool      `json:"ok"`
	DurationMS  float64   `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
}

type relayCheckReport struct {
	At           time.Time          `json:"at"`
	ControlError string             `json:"control_error,omitempty"`
	Probes       []relayProbeResult `json:"probes"`
}

func relayEchoProbe(kind string, size int) (result relayProbeResult) {
	result.Kind, result.Size = kind, size
	start := time.Now()
	result.At = start
	defer func() { result.DurationMS = float64(time.Since(start)) / float64(time.Millisecond) }()
	err := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		deadline, _ := ctx.Deadline()
		var d net.Dialer
		conn, err := d.DialContext(ctx, kind+"4", echoEndpoint())
		if err != nil {
			return err
		}
		defer conn.Close()
		if kind == "udp" && size > 1280 {
			if err := allowUDPFragmentation(conn.(*net.UDPConn)); err != nil {
				return err
			}
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n != len(payload) {
			return io.ErrShortWrite
		}
		reply := make([]byte, size)
		if kind == "tcp" {
			_, err = io.ReadFull(conn, reply)
		} else {
			// An extra byte detects an oversized datagram, not just its prefix.
			reply = make([]byte, size+1)
			n, err = conn.Read(reply)
			reply = reply[:n]
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, reply) {
			return fmt.Errorf("echo payload mismatch")
		}
		return nil
	}()
	result.OK = err == nil
	if err != nil {
		result.Error = err.Error()
		result.FailureKind = "unexpected"
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			result.FailureKind = "timeout"
		} else if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ECONNREFUSED) {
			result.FailureKind = "unreachable"
		}
	}
	return result
}

func runRelayCheck() error {
	report := relayCheckReport{At: time.Now(), Probes: make([]relayProbeResult, 4)}
	var wg sync.WaitGroup
	for i, item := range []struct {
		kind string
		size int
	}{{"udp", 32}, {"tcp", 32}, {"udp", 1400}, {"tcp", 1400}} {
		wg.Add(1)
		go func(i int, kind string, size int) { defer wg.Done(); report.Probes[i] = relayEchoProbe(kind, size) }(i, item.kind, item.size)
	}
	// This uses the VPN address; a working underlay management path cannot mask
	// a missing tunnel. Forwarding faults must not disrupt this local service.
	client := api.NewCredentialClient("https://10.77.0.1:8443", os.Getenv("VPNCTL_PKI"))
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err := client.FleetStatus(ctx)
	cancel()
	if err != nil {
		report.ControlError = err.Error()
	}
	wg.Wait()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(os.Getenv("VPNCTL_RELAY_REPORT"), data, 0600)
}

func verifyEchoSources(t *testing.T, results string, configs []config.Config) {
	t.Helper()
	f, err := os.Open(filepath.Join(results, "uplink-sources.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var observation echoObservation
		if err := json.Unmarshal(scanner.Bytes(), &observation); err != nil {
			t.Fatal(err)
		}
		seen[observation.Kind+"/"+observation.Source] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	var addresses []string
	for _, cfg := range configs {
		addresses = append(addresses, strings.Split(cfg.Node.VPNIP, "/")[0])
	}
	addresses = append(addresses, relayGatewayIP)
	for _, ip := range addresses {
		for _, kind := range []string{"udp", "tcp"} {
			if !seen[kind+"/"+ip] {
				t.Errorf("target never observed %s source %s", kind, ip)
			}
		}
	}
}
