// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkapi

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/relayapply"
)

const (
	MaxConnections  = 16
	MaxStreams      = 4
	MaxRecordBytes  = 4096
	MaxRequestBytes = 4096
	MaxStreamBytes  = 64 << 10
	StreamLifetime  = 30 * time.Second
	writeTimeout    = 200 * time.Millisecond
)

type Source interface {
	Snapshot() relayapply.UplinkSnapshot
}
type Options struct {
	Directory   string
	AllowedUIDs []uint32
}
type Frame struct {
	SchemaVersion int                       `json:"schema_version"`
	Type          string                    `json:"type"`
	Cursor        string                    `json:"cursor"`
	Snapshot      relayapply.UplinkSnapshot `json:"snapshot"`
}
type Statistics struct {
	SchemaVersion int    `json:"schema_version"`
	Running       bool   `json:"running"`
	Connections   int    `json:"connections"`
	Streams       int    `json:"streams"`
	Accepted      uint64 `json:"accepted,string"`
	Denied        uint64 `json:"denied,string"`
	Limited       uint64 `json:"limited,string"`
	Malformed     uint64 `json:"malformed,string"`
}
type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) allow(now time.Time, rate float64) bool {
	if b.at.IsZero() {
		b.tokens = rate
	} else {
		b.tokens = min(rate, b.tokens+now.Sub(b.at).Seconds()*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type peerBudget struct {
	requests bucket
	streams  int
}
type Server struct {
	listener         *ownedListener
	source           Source
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	once             sync.Once
	mu               sync.Mutex // API admission only; never acquired by the route producer.
	peers            map[uint32]*peerBudget
	global           bucket
	conns            map[*net.UnixConn]struct{}
	stats            Statistics
	frameMu          sync.Mutex
	incarnation, key string
	sequence         uint64
	lastProducer     string
	lastRevision     uint64
	frameKind        string
}

func Start(parent context.Context, options Options, source Source) (*Server, error) {
	if source == nil || len(options.AllowedUIDs) == 0 || len(options.AllowedUIDs) > 16 {
		return nil, errors.New("source and 1..16 allowed UIDs required")
	}
	s := &Server{source: source, peers: make(map[uint32]*peerBudget), conns: make(map[*net.UnixConn]struct{}), stats: Statistics{SchemaVersion: 1, Running: true}}
	for _, uid := range options.AllowedUIDs {
		if s.peers[uid] != nil {
			return nil, errors.New("duplicate allowed UID")
		}
		s.peers[uid] = new(peerBudget)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	s.incarnation = hex.EncodeToString(id[:])
	listener, err := listen(options.Directory)
	if err != nil {
		return nil, err
	}
	s.listener = listener
	s.ctx, s.cancel = context.WithCancel(parent)
	s.wg.Add(1)
	go s.accept()
	go func() {
		select {
		case <-parent.Done():
			s.Close()
		case <-s.ctx.Done():
		}
	}()
	return s, nil
}
func (s *Server) Close() {
	s.once.Do(func() {
		s.cancel()
		s.listener.Close()
		s.mu.Lock()
		s.stats.Running = false
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}
func (s *Server) Stats() Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.stats
	v.Connections = len(s.conns)
	return v
}

// Pace accept itself: an unauthorized connection flood cannot create unbounded
// handlers or a busy rejection loop. Excess connections remain in the bounded
// kernel listen backlog. HTTP keepalive/pipelining are deliberately unsupported.
func (s *Server) accept() {
	defer s.wg.Done()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
		c, err := s.listener.AcceptUnix()
		if err != nil {
			go s.Close()
			return
		}
		uid, err := peerUID(c)
		s.mu.Lock()
		peer := s.peers[uid]
		if err != nil || peer == nil {
			s.stats.Denied++
			s.mu.Unlock()
			c.Close()
			continue
		}
		now := time.Now()
		if s.ctx.Err() != nil || len(s.conns) >= MaxConnections || !s.global.allow(now, 16) || !peer.requests.allow(now, 8) {
			s.stats.Limited++
			s.mu.Unlock()
			reply(c, 429, []byte(`{"error":"overloaded"}`), 5*time.Millisecond)
			c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.stats.Accepted++
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer c.Close()
			defer func() { s.mu.Lock(); delete(s.conns, c); s.mu.Unlock() }()
			s.handle(c, uid)
		}()
	}
}

func reply(c *net.UnixConn, status int, body []byte, timeout time.Duration) error {
	c.SetWriteDeadline(time.Now().Add(timeout))
	_, err := fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	return err
}
func (s *Server) reject(c *net.UnixConn, status int) {
	s.mu.Lock()
	s.stats.Malformed++
	s.mu.Unlock()
	_ = reply(c, status, []byte(`{"error":"invalid_request"}`), writeTimeout)
}

func (s *Server) handle(c *net.UnixConn, uid uint32) {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	limited := &io.LimitedReader{R: c, N: MaxRequestBytes + 1}
	r, err := http.ReadRequest(bufio.NewReaderSize(limited, MaxRequestBytes+1))
	if err != nil || limited.N == 0 {
		s.reject(c, 400)
		return
	}
	if r.Method != "GET" {
		s.reject(c, 405)
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.URL.IsAbs() || r.URL.RawPath != "" {
		s.reject(c, 400)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.reject(c, 400)
		return
	}
	if r.URL.Path != "/v1/events" && len(q) != 0 {
		s.reject(c, 400)
		return
	}
	switch r.URL.Path {
	case "/v1/health":
		b, _ := json.Marshal(s.Stats())
		_ = reply(c, 200, b, writeTimeout)
	case "/v1/status":
		frame, err := s.sample()
		if err != nil {
			_ = reply(c, 503, []byte(`{"error":"snapshot_unavailable"}`), writeTimeout)
			return
		}
		b, _ := json.Marshal(frame)
		_ = reply(c, 200, b, writeTimeout)
	case "/v1/events":
		after := q.Get("after")
		if len(q) > 1 || len(q) == 1 && (len(q["after"]) != 1 || !validCursor(after)) {
			s.reject(c, 400)
			return
		}
		s.stream(c, uid, after)
	default:
		s.reject(c, 404)
	}
}

func validCursor(v string) bool {
	if len(v) < 34 || len(v) > 53 || v[32] != ':' {
		return false
	}
	b, err := hex.DecodeString(v[:32])
	if err != nil || len(b) != 16 || strings.ToLower(v[:32]) != v[:32] {
		return false
	}
	n, err := strconv.ParseUint(v[33:], 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v[33:]
}

func (s *Server) sample() (Frame, error) {
	s.frameMu.Lock()
	defer s.frameMu.Unlock()
	snap := s.source.Snapshot()
	stable := snap
	stable.ObservedAgeMS = nil
	stable.RemainingValidityMS = 0
	b, err := json.Marshal(stable)
	if err != nil || len(b) > 2048 {
		return Frame{}, errors.New("snapshot exceeds bound")
	}
	if string(b) != s.key {
		if s.sequence == ^uint64(0) {
			return Frame{}, errors.New("cursor exhausted")
		}
		s.sequence++
		s.key = string(b)
		s.frameKind = "snapshot"
		if s.lastProducer != "" && (snap.ProducerID != s.lastProducer || snap.Revision < s.lastRevision || snap.Revision > s.lastRevision && snap.Revision-s.lastRevision > 1) {
			s.frameKind = "reset"
		}
		s.lastProducer, s.lastRevision = snap.ProducerID, snap.Revision
	}
	return Frame{SchemaVersion: 1, Type: s.frameKind, Cursor: s.incarnation + ":" + strconv.FormatUint(s.sequence, 10), Snapshot: snap}, nil
}

func (s *Server) stream(c *net.UnixConn, uid uint32, after string) {
	s.mu.Lock()
	p := s.peers[uid]
	if s.stats.Streams >= MaxStreams || p.streams >= 2 {
		s.stats.Limited++
		s.mu.Unlock()
		_ = reply(c, 429, []byte(`{"error":"overloaded"}`), writeTimeout)
		return
	}
	s.stats.Streams++
	p.streams++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.stats.Streams--; p.streams--; s.mu.Unlock() }()
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"); err != nil {
		return
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	end := time.NewTimer(StreamLifetime)
	defer end.Stop()
	sent := 0
	last := ""
	lastWrite := time.Time{}
	for {
		frame, err := s.sample()
		if err != nil {
			return
		}
		if last == "" || frame.Cursor != last || time.Since(lastWrite) >= 5*time.Second {
			// Only the latest record is retained. Never silently pretend that a
			// missing intermediate transition was delivered to a slow subscriber.
			if last == "" && after != "" && after != frame.Cursor || last != "" && frame.Cursor != last && !successor(last, frame.Cursor) {
				frame.Type = "reset"
			}
			b, err := json.Marshal(frame)
			if err != nil || len(b)+1 > MaxRecordBytes || sent+len(b)+1 > MaxStreamBytes {
				return
			}
			c.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err = c.Write(append(b, '\n')); err != nil {
				return
			}
			sent += len(b) + 1
			last = frame.Cursor
			lastWrite = time.Now()
		}
		select {
		case <-s.ctx.Done():
			return
		case <-end.C:
			return
		case <-tick.C:
		}
	}
}
func successor(old, next string) bool {
	if !validCursor(old) || !validCursor(next) || old[:32] != next[:32] {
		return false
	}
	a, _ := strconv.ParseUint(old[33:], 10, 64)
	b, _ := strconv.ParseUint(next[33:], 10, 64)
	return a != ^uint64(0) && b == a+1
}
