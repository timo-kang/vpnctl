// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
)

func TestSilentFleetDoesNotStarveHeartbeatOrHealth(t *testing.T) {
	baseline := runtime.NumGoroutine()
	fdsBefore, _ := os.ReadDir("/proc/self/fd")
	t.Run("matrix", func(t *testing.T) {
		for _, size := range []int{1, 3, 8, 32} {
			for _, slow := range []bool{false, true} {
				t.Run(fmt.Sprintf("peers_%d_slow_%t", size, slow), func(t *testing.T) {
					t.Parallel()
					silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						t.Fatal(err)
					}
					defer silent.Close()
					health, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						t.Fatal(err)
					}
					defer health.Close()
					var healthy atomic.Bool
					healthy.Store(true)
					var healthCalls atomic.Int32
					readerDone := make(chan struct{})
					go func() {
						defer close(readerDone)
						buf := make([]byte, 2048)
						for {
							n, addr, err := health.ReadFromUDP(buf)
							if err != nil {
								return
							}
							healthCalls.Add(1)
							if healthy.Load() {
								health.WriteToUDP(buf[:n], addr)
							}
						}
					}()
					defer func() { health.Close(); <-readerDone }()
					peers := make([]api.PeerCandidate, size)
					for i := range peers {
						peers[i] = api.PeerCandidate{ID: fmt.Sprintf("peer-%d", i), PublicAddr: silent.LocalAddr().String(), ProbePort: silent.LocalAddr().(*net.UDPAddr).Port}
					}
					var lastRegister atomic.Int64
					var reports, inFlight, maxInFlight atomic.Int32
					ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						switch r.URL.Path {
						case "/register":
							lastRegister.Store(time.Now().UnixNano())
							json.NewEncoder(w).Encode(api.RegisterResponse{NodeID: "node", VPNIP: "10.7.0.2/32"})
						case "/candidates":
							json.NewEncoder(w).Encode(api.CandidatesResponse{Peers: peers})
						case "/direct-result":
							io.Copy(io.Discard, r.Body)
							reports.Add(1)
							current := inFlight.Add(1)
							defer inFlight.Add(-1)
							for old := maxInFlight.Load(); current > old && !maxInFlight.CompareAndSwap(old, current); old = maxInFlight.Load() {
							}
							if slow {
								<-r.Context().Done()
								return
							}
							w.WriteHeader(204)
						default:
							w.WriteHeader(204)
						}
					}))
					defer ctrl.Close()
					reservation, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						t.Fatal(err)
					}
					port := reservation.LocalAddr().(*net.UDPAddr).Port
					reservation.Close()
					cfg := config.NodeConfig{Name: "node", Controller: ctrl.URL, ProbePort: port, DirectMode: "auto", KeepaliveIntervalSec: 1, STUNIntervalSec: 60, CandidatesIntervalSec: 1, DirectIntervalSec: 1, ServerPublicKey: "unused", ServerEndpoint: "127.0.0.1:51820", ServerAllowedIPs: []string{"127.0.0.0/24"}, ServerProbePort: health.LocalAddr().(*net.UDPAddr).Port, HealthCheckIntervalSec: 1, HealthCheckTimeoutSec: 1, HealthCheckFailures: 2}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- Run(ctx, cfg) }()
					joined := false
					defer func() {
						cancel()
						if !joined {
							select {
							case <-done:
							case <-time.After(2 * time.Second):
								t.Error("worker shutdown leaked")
							}
						}
					}()
					start := time.Now()
					maxAge := time.Duration(0)
					for time.Since(start) < 6*time.Second {
						select {
						case err := <-done:
							joined = true
							t.Fatalf("agent stopped with healthy hub: %v", err)
						default:
						}
						if at := lastRegister.Load(); at != 0 {
							age := time.Since(time.Unix(0, at))
							if age > maxAge {
								maxAge = age
							}
							if age > 2500*time.Millisecond {
								t.Fatalf("heartbeat stalled %v with %d silent peers", age, size)
							}
						}
						time.Sleep(50 * time.Millisecond)
					}
					if reports.Load() == 0 || healthCalls.Load() < 3 {
						t.Fatalf("fault paths not exercised: reports=%d health=%d", reports.Load(), healthCalls.Load())
					}
					if maxInFlight.Load() > directBatchSize {
						t.Fatalf("unbounded requests: %d", maxInFlight.Load())
					}
					healthy.Store(false)
					failedAt := time.Now()
					select {
					case err := <-done:
						joined = true
						if !errors.Is(err, ErrTunnelDead) {
							t.Fatal(err)
						}
					case <-time.After(4 * time.Second):
						t.Fatal("health failure starved by direct/API I/O")
					}
					t.Logf("silent_peers=%d slow_api=%t max_heartbeat_age=%v health_detection=%v max_direct_requests=%d", size, slow, maxAge, time.Since(failedAt), maxInFlight.Load())
				})
			}
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		after, _ := os.ReadDir("/proc/self/fd")
		if runtime.NumGoroutine() <= baseline+2 && len(after) <= len(fdsBefore)+2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resources did not return: goroutines before=%d after=%d fds before=%d after=%d", baseline, runtime.NumGoroutine(), len(fdsBefore), len(after))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
