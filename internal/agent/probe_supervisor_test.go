// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vpnctl/internal/config"
	"vpnctl/internal/direct"
)

func availableProbePort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

func TestProbeResponderDuringBlockedInitialRegistration(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := availableProbePort(t)
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, config.NodeConfig{Name: "robot", Controller: server.URL, ProbePort: port})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("registration cancellation leaked session")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("registration not reached")
	}
	if _, err := direct.ProbePeer(ctx, "127.0.0.1:0", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err != nil {
		t.Fatal("blocked registration disabled independent probe responder", err)
	}
}

func TestProbeSupervisorRetriesPortReloadAndClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "registration unavailable", 503) }))
	defer server.Close()
	var probes ProbeSupervisor
	defer probes.Close()
	cfg := config.NodeConfig{Name: "robot", Controller: server.URL, ProbePort: availableProbePort(t)}
	if err := probes.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	original := probes.shared
	probe := func(port int) {
		t.Helper()
		if _, err := direct.ProbePeer(context.Background(), "127.0.0.1:0", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		if err := probes.RunSession(context.Background(), cfg); err == nil {
			t.Fatal("registration failure hidden")
		}
		if probes.shared != original {
			t.Fatal("retry replaced probe socket")
		}
		probe(cfg.ProbePort)
	}
	busy, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	unavailable := cfg
	unavailable.ProbePort = busy.LocalAddr().(*net.UDPAddr).Port
	if err := probes.Configure(unavailable); err == nil {
		t.Fatal("duplicate bind accepted")
	}
	if probes.shared != original {
		t.Fatal("failed replacement discarded working responder")
	}
	probe(cfg.ProbePort)
	oldPort := cfg.ProbePort
	cfg.ProbePort = availableProbePort(t)
	if err := probes.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	probe(cfg.ProbePort)
	old, err := net.ListenPacket("udp", fmt.Sprintf(":%d", oldPort))
	if err != nil {
		t.Fatal("old socket leaked", err)
	}
	old.Close()
	disabled := cfg
	disabled.ProbePort = -1
	if err := probes.Configure(disabled); err != nil {
		t.Fatal(err)
	}
	if probes.shared != nil {
		t.Fatal("disabled responder retained")
	}
	if err := probes.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	probe(cfg.ProbePort)
	probes.Close()
	probes.Close()
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.ProbePort))
	if err != nil {
		t.Fatal("shutdown socket leaked", err)
	}
	conn.Close()
}
