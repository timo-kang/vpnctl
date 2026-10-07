//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// Host-safe: net.Pipe uses no kernel interface or network configuration.
func TestManagerStreamRetainsPartialFrameAcrossTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(server, nonce); err != nil {
			finished <- err
			return
		}
		if _, err := server.Write([]byte("198.18.0")); err != nil {
			finished <- err
			return
		}
		time.Sleep(450 * time.Millisecond)
		if _, err := server.Write(append([]byte(".11:1234\n"), nonce[:3]...)); err != nil {
			finished <- err
			return
		}
		time.Sleep(450 * time.Millisecond)
		_, err := server.Write(nonce[3:])
		finished <- err
	}()
	stream := managerStream{c: client, reader: bufio.NewReader(client)}
	for i := 0; i < 2; i++ {
		_, err := stream.exchange()
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("expected timeout %d: %v", i, err)
		}
	}
	sent := stream.sentAt
	source, err := stream.exchange()
	if err != nil || source != "198.18.0.11" || stream.sentAt != sent {
		t.Fatalf("lost pending frame: %q %v", source, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestManagerStreamRejectsCorruptNonce(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(server, nonce); err == nil {
			nonce[0] ^= 1
			server.Write(append([]byte("198.18.0.11:1234\n"), nonce...))
		}
	}()
	stream := managerStream{c: client, reader: bufio.NewReader(client)}
	if _, err := stream.exchange(); !errors.Is(err, errManagerProtocol) {
		t.Fatalf("corruption treated as outage: %v", err)
	}
	if _, err := stream.exchange(); !errors.Is(err, errManagerProtocol) {
		t.Fatalf("fatal corruption not retained: %v", err)
	}
}
