// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package stunutil

import (
	"context"
	"errors"
	"github.com/pion/stun/v3"
	"net"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	if got := Classify([]string{"1.2.3.4:1"}); got != NATTypeUnknown {
		t.Fatalf("got=%q", got)
	}
	if got := Classify([]string{"1.2.3.4:1", "1.2.3.4:1"}); got != NATTypeConeOrRestricted {
		t.Fatalf("got=%q", got)
	}
	if got := Classify([]string{"1.2.3.4:1", "1.2.3.4:2"}); got != NATTypeSymmetric {
		t.Fatalf("got=%q", got)
	}
}

func TestProbeDNSUsesTimeout(t *testing.T) {
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	defer func() { net.DefaultResolver = old }()
	start := time.Now()
	_, err := probeServer(context.Background(), "unresolvable.invalid:3478", 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("DNS not bounded: %v", err)
	}
}

func TestProbeCancellationStopsSweep(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	received := make(chan struct{})
	go func() { var b [2048]byte; _, _, _ = conn.ReadFrom(b[:]); close(received) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := Probe(ctx, []string{conn.LocalAddr().String(), "unused.invalid"}, time.Minute)
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("probe not sent")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe cancellation stuck")
	}
	for i := 0; i < 25; i++ {
		_, _, err := Probe(ctx, []string{conn.LocalAddr().String()}, time.Minute)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestProbeRetriesAndSilentServerTimeout(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		var b [2048]byte
		for i := 0; i < 2; i++ {
			n, addr, err := conn.ReadFrom(b[:])
			if err != nil {
				done <- err
				return
			}
			if i == 0 {
				continue
			} // first packet loss must preserve Pion retransmission
			msg := &stun.Message{Raw: append([]byte(nil), b[:n]...)}
			if err := msg.Decode(); err != nil {
				done <- err
				return
			}
			response, err := stun.Build(stun.NewTransactionIDSetter(msg.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("192.0.2.10"), Port: 12345})
			if err == nil {
				_, err = conn.WriteTo(response.Raw, addr)
			}
			done <- err
		}
	}()
	addr, kind, err := Probe(context.Background(), []string{conn.LocalAddr().String()}, 2*time.Second)
	if err != nil || addr != "192.0.2.10:12345" || kind != NATTypeUnknown {
		t.Fatalf("%s %s %v", addr, kind, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_, _, err := Probe(context.Background(), []string{conn.LocalAddr().String()}, 10*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline lost: %v", err)
		}
	}
}
