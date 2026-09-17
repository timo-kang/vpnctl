// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
)

type probeEvent struct {
	Node        string          `json:"node"`
	Phase       string          `json:"phase"`
	EndPhase    string          `json:"end_phase,omitempty"`
	Kind        string          `json:"kind"`
	At          time.Time       `json:"at"`
	DurationMS  float64         `json:"duration_ms"`
	OK          bool            `json:"ok"`
	Reconnected bool            `json:"reconnected,omitempty"`
	Error       string          `json:"error,omitempty"`
	HTTP        *httpMilestones `json:"http,omitempty"`
}

// Re-exec the compiled test binary inside a node netns. All API and socket calls
// therefore use the kernel routing table of that node, not the test coordinator.
func TestNetworkWorker(t *testing.T) {
	mode := os.Getenv("VPNCTL_WORKER")
	if mode == "" {
		return
	}
	var err error
	switch mode {
	case "monitor-http":
		path := os.Getenv("VPNCTL_MONITOR_PATH")
		if path != "/network/quality" && path != "/metrics" {
			err = fmt.Errorf("invalid monitor path")
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:19100"+path, nil)
		resp, getErr := http.DefaultClient.Do(req)
		if getErr != nil {
			err = getErr
			break
		}
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("monitor status %d", resp.StatusCode)
		} else {
			_, err = io.Copy(os.Stdout, resp.Body)
		}
		resp.Body.Close()
	case "plaintext-metrics":
		resp, getErr := http.Get("http://10.77.0.1:8080/prom/metrics")
		if getErr != nil {
			err = getErr
			break
		}
		_, err = io.Copy(os.Stdout, resp.Body)
		resp.Body.Close()
	case "echo":
		err = serveEcho()
	case "telemetry":
		err = collectTelemetry()
	case "probe":
		err = runNetworkProbes()
	case "relay-check":
		err = runRelayCheck()
	case "replay":
		c := api.NewCredentialClient("https://10.77.0.1:8443", os.Getenv("VPNCTL_PKI"))
		defer c.CloseIdleConnections()
		csr, _, generateErr := pki.GenerateCSR("forged-identity")
		if generateErr != nil {
			err = generateErr
			break
		}
		for i := 0; i < 50; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, fleetErr := c.FleetStatus(ctx)
			_, renewErr := c.Renew(ctx, string(csr))
			cancel()
			if fleetErr == nil || renewErr == nil || !strings.Contains(fleetErr.Error(), "403 Forbidden") || !strings.Contains(renewErr.Error(), "403 Forbidden") {
				err = fmt.Errorf("revoked replay %d must be rejected by authorization: fleet=%v renew=%v", i, fleetErr, renewErr)
				break
			}
		}
	case "register":
		c := api.NewClient("http://127.0.0.1:8080")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = c.Register(ctx, api.RegisterRequest{Name: os.Getenv("VPNCTL_REGISTER_NAME"), PubKey: os.Getenv("VPNCTL_REGISTER_KEY")})
		if os.Getenv("VPNCTL_EXPECT_FAILURE") == "1" {
			if err == nil || !strings.Contains(err.Error(), "500 Internal Server Error") {
				err = fmt.Errorf("expected failed mutation, got %v", err)
			} else {
				err = nil
			}
		}
	case "fleet":
		c := api.NewCredentialClient("https://10.77.0.1:8443", os.Getenv("VPNCTL_PKI"))
		defer c.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = c.FleetStatus(ctx)
	default:
		err = fmt.Errorf("unknown network worker: %s", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func serveEcho() error {
	observe, closeObservations, err := echoObserver()
	if err != nil {
		return err
	}
	defer closeObservations()
	udp, err := net.ListenPacket("udp4", echoEndpoint())
	if err != nil {
		return err
	}
	defer udp.Close()
	if os.Getenv("VPNCTL_ECHO_FRAGMENT") == "1" {
		if err := allowUDPFragmentation(udp.(*net.UDPConn)); err != nil {
			return err
		}
	}
	tcp, err := net.Listen("tcp4", echoEndpoint())
	if err != nil {
		return err
	}
	defer tcp.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if err := observe("udp", addr); err != nil {
				_ = tcp.Close()
				return
			}
			if _, err := udp.WriteTo(buf[:n], addr); err != nil {
				fmt.Fprintf(os.Stderr, "udp echo reply bytes=%d: %v\n", n, err)
			}
		}
	}()
	for {
		conn, err := tcp.Accept()
		if err != nil {
			return err
		}
		if err := observe("tcp", conn.RemoteAddr()); err != nil {
			conn.Close()
			return err
		}
		go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
	}
}

func runNetworkProbes() error {
	path := os.Getenv("VPNCTL_EVENTS")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	encoder := json.NewEncoder(f)
	emit := func(e probeEvent) {
		mu.Lock()
		defer mu.Unlock()
		if err := encoder.Encode(e); err != nil {
			cancel()
		}
	}
	phase := func() string { data, _ := os.ReadFile(os.Getenv("VPNCTL_PHASE")); return string(data) }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := runUDPProbes(ctx, phase, emit); err != nil {
			cancel()
		}
	}()
	for _, kind := range []string{"tcp", "https"} {
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			client := api.NewCredentialClient("https://10.77.0.1:8443", os.Getenv("VPNCTL_PKI"))
			defer client.CloseIdleConnections()
			var conn net.Conn
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			interval := 20 * time.Millisecond
			if kind == "tcp" {
				interval = 50 * time.Millisecond
			}
			if kind == "https" {
				interval = 100 * time.Millisecond
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			sequence := 0
			connectedBefore := false
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				stage := phase()
				if stage == "done" {
					return
				}
				start := time.Now()
				e := probeEvent{Node: os.Getenv("VPNCTL_NODE"), Phase: stage, Kind: kind, At: start}
				var probeErr error
				if kind == "https" {
					// Fresh TLS handshakes exercise server certificate reload too.
					client.CloseIdleConnections()
					reqCtx, stop := context.WithTimeout(ctx, time.Second)
					tracedCtx, trace := tracedProbe(reqCtx, start)
					_, probeErr = client.FleetStatus(tracedCtx)
					e.HTTP = trace.snapshot()
					stop()
				} else {
					if conn == nil {
						d := net.Dialer{Timeout: 500 * time.Millisecond}
						conn, probeErr = d.DialContext(ctx, kind+"4", echoEndpoint())
						if probeErr == nil && kind == "tcp" {
							e.Reconnected = connectedBefore
							connectedBefore = true
						}
					}
					if probeErr == nil {
						_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
						payload := []byte(fmt.Sprintf("%032s", strconv.Itoa(sequence)))
						sequence++
						_, probeErr = conn.Write(payload)
						if probeErr == nil {
							reply := make([]byte, len(payload))
							_, probeErr = io.ReadFull(conn, reply)
							if probeErr == nil && !bytes.Equal(payload, reply) {
								probeErr = fmt.Errorf("echo sequence mismatch")
							}
						}
					}
					if probeErr != nil && conn != nil {
						conn.Close()
						conn = nil
					}
				}
				e.DurationMS = float64(time.Since(start)) / float64(time.Millisecond)
				e.EndPhase = phase()
				e.OK = probeErr == nil
				if probeErr != nil {
					e.Error = probeErr.Error()
				}
				emit(e)
			}
		}(kind)
	}
	wg.Wait()
	return ctx.Err()
}

// Keep UDP sends independent of receive timeouts so a loss burst does not reduce
// the sampling rate and make the measured packet-loss ratio look artificially low.
func runUDPProbes(parent context.Context, phase func() string, emit func(probeEvent)) error {
	target, err := net.ResolveUDPAddr("udp4", echoEndpoint())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		cancel()
		return err
	}
	type reply struct {
		sequence string
		at       time.Time
	}
	replies := make(chan reply, 128)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.Equal(target.IP) || from.Port != target.Port {
				continue
			}
			select {
			case replies <- reply{string(buf[:n]), time.Now()}:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); conn.Close(); <-readerDone }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	pending := make(map[string]probeEvent)
	sequence := 0
	finish := func(key string, e probeEvent, at time.Time, err error) {
		delete(pending, key)
		e.DurationMS = float64(at.Sub(e.At)) / float64(time.Millisecond)
		e.OK = err == nil
		if err != nil {
			e.Error = err.Error()
		}
		emit(e)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case response := <-replies:
			if e, ok := pending[response.sequence]; ok {
				var err error
				if response.at.Sub(e.At) > 500*time.Millisecond {
					err = fmt.Errorf("UDP echo exceeded 500ms deadline")
				}
				finish(response.sequence, e, response.at, err)
			}
		case <-ticker.C:
			now := time.Now()
			for key, e := range pending {
				if now.Sub(e.At) >= 500*time.Millisecond {
					finish(key, e, now, fmt.Errorf("UDP echo timeout"))
				}
			}
			stage := phase()
			if stage == "done" {
				if len(pending) == 0 {
					return nil
				}
				continue
			}
			key := fmt.Sprintf("%032d", sequence)
			sequence++
			e := probeEvent{Node: os.Getenv("VPNCTL_NODE"), Phase: stage, Kind: "udp", At: now}
			pending[key] = e
			_ = conn.SetWriteDeadline(now.Add(500 * time.Millisecond))
			if _, err := conn.WriteToUDP([]byte(key), target); err != nil {
				finish(key, e, time.Now(), err)
			}
		}
	}
}
