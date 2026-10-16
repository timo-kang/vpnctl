// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"vpnctl/internal/relayapply"
)

type testSource struct {
	value atomic.Pointer[relayapply.UplinkSnapshot]
}

func (s *testSource) Snapshot() relayapply.UplinkSnapshot { return *s.value.Load() }
func sourceFixture() *testSource {
	s := new(testSource)
	s.value.Store(&relayapply.UplinkSnapshot{SchemaVersion: 1, TargetID: "app", ProducerID: strings.Repeat("a", 32), Revision: 1, Availability: "unknown", Freshness: "unknown", Reason: "observation_unavailable", SessionContinuity: "not_established"})
	return s
}
func apiFixture(t *testing.T) (*Server, *testSource, string) {
	t.Helper()
	dir := testRuntime(t)
	source := sourceFixture()
	s, err := Start(context.Background(), Options{Directory: dir, AllowedUIDs: []uint32{uint32(os.Geteuid())}}, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, source, dir
}
func request(t *testing.T, dir, path string) (*http.Response, net.Conn) {
	t.Helper()
	c, err := Dial(context.Background(), dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: uplink\r\n\r\n", path); err != nil {
		t.Fatal(err)
	}
	r, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Body.Close(); c.Close() })
	return r, c
}

func TestHTTPStatusEventsExpiryAndCursorReset(t *testing.T) {
	_, source, dir := apiFixture(t)
	r, _ := request(t, dir, "/v1/status")
	var first Frame
	if r.StatusCode != 200 || json.NewDecoder(r.Body).Decode(&first) != nil || first.Snapshot.TargetID != "app" {
		t.Fatal("status contract")
	}
	r.Body.Close()
	r, _ = request(t, dir, "/v1/events?after="+first.Cursor)
	decoder := json.NewDecoder(r.Body)
	var event Frame
	if decoder.Decode(&event) != nil || event.Type != "snapshot" || event.Cursor != first.Cursor {
		t.Fatal("initial full snapshot")
	}
	stale := source.Snapshot()
	stale.Freshness = "stale"
	source.value.Store(&stale)
	if decoder.Decode(&event) != nil || event.Cursor == first.Cursor || event.Snapshot.Freshness != "stale" {
		t.Fatal("expiry without new publication was hidden")
	}
	r.Body.Close()
	r, _ = request(t, dir, "/v1/events?after="+first.Cursor)
	if json.NewDecoder(r.Body).Decode(&event) != nil || event.Type != "reset" || event.Snapshot.Freshness != "stale" {
		t.Fatal("old cursor not explicitly reset")
	}
}

func TestHTTPRejectsUnsupportedAndMalformedRequests(t *testing.T) {
	for _, path := range []string{"/v1/events?after=truncated", "/v1/events?after=", "/v1/events?other=1", "/v1/status?after=x", "/admin"} {
		t.Run(path, func(t *testing.T) {
			_, _, dir := apiFixture(t)
			r, _ := request(t, dir, path)
			if r.StatusCode != 400 && r.StatusCode != 404 {
				t.Fatal("invalid route/query accepted", r.StatusCode)
			}
		})
	}
	_, _, dir := apiFixture(t)
	c, err := Dial(context.Background(), dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "GET /v1/status HTTP/1.1\r\nHost: uplink\r\nX-Fill: %s\r\n\r\n", strings.Repeat("a", 8192))
	r, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil && r.StatusCode == 200 {
		t.Fatal("oversized headers accepted")
	}
}

func TestUIDDenialAndStreamLimits(t *testing.T) {
	dir := testRuntime(t)
	s, err := Start(context.Background(), Options{Directory: dir, AllowedUIDs: []uint32{uint32(os.Geteuid()) + 1}}, sourceFixture())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(context.Background(), dir, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(c, "GET /v1/status HTTP/1.1\r\nHost: uplink\r\n\r\n")
	b, _ := io.ReadAll(c)
	c.Close()
	s.Close()
	if strings.Contains(string(b), "snapshot") || s.Stats().Denied != 1 {
		t.Fatal("unauthorized state exposed")
	}
	s, _, dir = apiFixture(t)
	for i := 0; i < 2; i++ {
		r, _ := request(t, dir, "/v1/events")
		if r.StatusCode != 200 {
			t.Fatal("stream admission")
		}
	}
	r, _ := request(t, dir, "/v1/events")
	if r.StatusCode != 429 {
		t.Fatal("per UID streams not bounded", r.StatusCode)
	}
	start := time.Now()
	s.Close()
	if time.Since(start) > 3*time.Second {
		t.Fatal("unbounded stop")
	}
}

func TestRestartResetsTransportCursor(t *testing.T) {
	s, source, dir := apiFixture(t)
	r, _ := request(t, dir, "/v1/status")
	var old Frame
	json.NewDecoder(r.Body).Decode(&old)
	r.Body.Close()
	s.Close()
	s, err := Start(context.Background(), Options{Directory: dir, AllowedUIDs: []uint32{uint32(os.Geteuid())}}, source)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, _ = request(t, dir, "/v1/events?after="+old.Cursor)
	var next Frame
	if json.NewDecoder(r.Body).Decode(&next) != nil || next.Type != "reset" || next.Cursor == old.Cursor {
		t.Fatal("restart accepted old cursor")
	}
}

func TestPublicationGapsAndProducerChangesAreExplicitResets(t *testing.T) {
	s, source, _ := apiFixture(t)
	first, _ := s.sample()
	next := source.Snapshot()
	next.Revision += 2
	source.value.Store(&next)
	gap, _ := s.sample()
	if gap.Type != "reset" || gap.Cursor == first.Cursor {
		t.Fatal("missing publication hidden")
	}
	next.ProducerID = strings.Repeat("b", 32)
	next.Revision = 1
	source.value.Store(&next)
	restarted, _ := s.sample()
	if restarted.Type != "reset" {
		t.Fatal("producer restart hidden")
	}
}

func TestBlockedStreamWriteHasDeadline(t *testing.T) {
	s, _, _ := apiFixture(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1]) // The peer deliberately never reads.
	f := os.NewFile(uintptr(pair[0]), "blocked-api-stream")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	u := c.(*net.UnixConn)
	defer u.Close()
	if err := u.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	u.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = u.Write(make([]byte, 64<<10))
	if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal("test did not fill socket send buffer", err)
	}
	u.SetWriteDeadline(time.Time{})
	start := time.Now()
	done := make(chan struct{})
	go func() { s.stream(u, uint32(os.Geteuid()), ""); close(done) }()
	select {
	case <-done:
		if time.Since(start) < writeTimeout/2 || s.Stats().Streams != 0 {
			t.Fatal("blocked stream did not expire and release admission")
		}
	case <-time.After(time.Second):
		u.Close()
		<-done
		t.Fatal("blocked stream ignored write deadline")
	}
}

func TestParentCancellationReleasesEndpointAndConnections(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		dir := testRuntime(t)
		parent, cancel := context.WithCancel(context.Background())
		alreadyCanceled := attempt%2 == 0
		if alreadyCanceled {
			cancel() // Both parent and derived Done channels are ready at startup.
		}
		s, err := Start(parent, Options{Directory: dir, AllowedUIDs: []uint32{uint32(os.Geteuid())}}, sourceFixture())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); s.Close() })
		if !alreadyCanceled {
			r, _ := request(t, dir, "/v1/events")
			decoder := json.NewDecoder(r.Body)
			var frame Frame
			if decoder.Decode(&frame) != nil {
				t.Fatal("stream setup")
			}
			cancel() // No explicit Close: cancellation owns endpoint cleanup.
			if decoder.Decode(&frame) == nil {
				t.Fatal("canceled stream remained open")
			}
		}
		until := time.Now().Add(time.Second)
		for time.Now().Before(until) {
			v := s.Stats()
			if !v.Running && v.Connections == 0 && v.Streams == 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		stats := s.Stats()
		if stats.Running || stats.Connections != 0 || stats.Streams != 0 {
			t.Fatal("parent cancellation left API active")
		}
		if _, err := os.Lstat(dir + "/" + socketName); !os.IsNotExist(err) {
			t.Fatal("parent cancellation retained socket", err)
		}
		replacement, err := listen(dir)
		if err != nil {
			t.Fatal("parent cancellation retained lock", err)
		}
		replacement.Close()
	}
}
