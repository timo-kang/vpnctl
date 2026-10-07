//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
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
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"vpnctl/internal/relayapply"
	"vpnctl/internal/relayobserve"
	"vpnctl/internal/relayselect"
)

var errManagerProtocol = errors.New("invalid manager probe reply")

func managerMono() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(err)
	}
	return ts.Nano()
}

type managerAutoEvent struct {
	Sent     int64  `json:"request_sent_monotonic_ns,omitempty"`
	Sequence int    `json:"sequence"`
	Kind     string `json:"kind"`
	Begin    int64  `json:"begin_monotonic_ns"`
	End      int64  `json:"end_monotonic_ns"`
	OK       bool   `json:"ok"`
	Source   string `json:"source,omitempty"`
	Error    string `json:"error,omitempty"`
	Session  int    `json:"session,omitempty"`
}
type managerAutoCycle struct {
	Observed          int64                     `json:"observed_monotonic_ns"`
	Target            string                    `json:"target"`
	Applied           bool                      `json:"applied"`
	Guarded           bool                      `json:"guarded"`
	Path              string                    `json:"path,omitempty"`
	Reason            string                    `json:"reason"`
	ApplicationReason string                    `json:"application_reason"`
	Generation        uint64                    `json:"generation"`
	Candidates        []relayselect.Candidate   `json:"candidates"`
	Diagnostics       *relayobserve.Diagnostics `json:"diagnostics"`
}
type managerAutoTrace struct {
	streamSession int
	warnings      int
	mu            sync.Mutex
	events        []managerAutoEvent
	cycles        []managerAutoCycle
	failure       string
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

func (r *managerAutoTrace) fail(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure == "" {
		r.failure = s
	}
}
func (r *managerAutoTrace) add(e managerAutoEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) >= 20000 {
		r.failure = "packet trace capacity exceeded"
		return
	}
	e.Sequence = len(r.events) + 1
	r.events = append(r.events, e)
}
func (r *managerAutoTrace) snapshot() ([]managerAutoEvent, []managerAutoCycle, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]managerAutoEvent(nil), r.events...), append([]managerAutoCycle(nil), r.cycles...), r.failure
}
func (r *managerAutoTrace) restartStream() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streamSession++
	return r.streamSession
}
func (r *managerAutoTrace) close() { r.cancel(); r.wg.Wait() }

// Complete a nonce reply without discarding a partial TCP frame on a timeout.
// The persistent sampler keeps the same socket and outstanding nonce throughout
// the experiment: a reconnect is never reported as existing-session survival.
type managerStream struct {
	sentAt int64
	c      net.Conn
	reader *bufio.Reader
	nonce  []byte
	line   []byte
	reply  []byte
	source string
	fatal  error
}

func (s *managerStream) exchange() (string, error) {
	if s.fatal != nil {
		return "", s.fatal
	}
	if s.nonce == nil {
		s.sentAt = managerMono()
		s.nonce = make([]byte, 16)
		if _, err := rand.Read(s.nonce); err != nil {
			return "", err
		}
		s.line = nil
		s.reply = nil
		s.source = ""
		s.c.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := s.c.Write(s.nonce); err != nil {
			s.fatal = err
			return "", err
		}
	}
	s.c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if s.source == "" {
		for {
			part, err := s.reader.ReadSlice('\n')
			s.line = append(s.line, part...)
			if len(s.line) > 80 {
				s.fatal = fmt.Errorf("%w: oversized echo frame", errManagerProtocol)
				return "", s.fatal
			}
			if err != nil {
				return "", err
			}
			break
		}
		source, _, err := net.SplitHostPort(strings.TrimSpace(string(s.line)))
		if err != nil {
			s.fatal = err
			return "", err
		}
		s.source = source
	}
	for len(s.reply) < 16 {
		b := make([]byte, 16-len(s.reply))
		n, err := s.reader.Read(b)
		s.reply = append(s.reply, b[:n]...)
		if err != nil {
			return "", err
		}
	}
	if !bytes.Equal(s.reply, s.nonce) {
		s.fatal = fmt.Errorf("%w: nonce mismatch", errManagerProtocol)
		return "", s.fatal
	}
	source := s.source
	s.nonce = nil
	return source, nil
}
func managerAutoTCP(target string) (string, error) {
	c, err := net.DialTimeout("tcp4", target+":9192", 400*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer c.Close()
	s := managerStream{c: c, reader: bufio.NewReader(c)}
	return s.exchange()
}
func managerAutoUDP() (string, error) {
	c, err := net.DialTimeout("udp4", m3Target+":9193", 400*time.Millisecond)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(400 * time.Millisecond))
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	if _, err = c.Write(nonce); err != nil {
		return "", err
	}
	b := make([]byte, 128)
	n, err := c.Read(b)
	if err != nil {
		return "", err
	}
	line, body, ok := bytes.Cut(b[:n], []byte{'\n'})
	if !ok || !bytes.Equal(body, nonce) {
		return "", fmt.Errorf("%w: bad UDP echo", errManagerProtocol)
	}
	source, _, err := net.SplitHostPort(string(line))
	if err != nil {
		return "", fmt.Errorf("%w: UDP source: %v", errManagerProtocol, err)
	}
	return source, nil
}
func serveManagerUDPEcho() error {
	c, err := net.ListenPacket("udp4", m3Target+":9193")
	if err != nil {
		return err
	}
	defer c.Close()
	b := make([]byte, 128)
	for {
		n, a, err := c.ReadFrom(b)
		if err != nil {
			return err
		}
		if n == 16 {
			reply := append([]byte(a.String()+"\n"), b[:n]...)
			if _, err = c.WriteTo(reply, a); err != nil {
				return err
			}
		}
	}
}
func startManagerAutoTrace(logs map[string]string) *managerAutoTrace {
	ctx, cancel := context.WithCancel(context.Background())
	r := &managerAutoTrace{cancel: cancel, streamSession: 1}
	jobs := map[string]func() (string, error){"tcp-new": func() (string, error) { return managerAutoTCP(m3Target) }, "udp": managerAutoUDP,
		"independent-app": func() (string, error) { return managerAutoTCP("198.18.0.3") }, "rf-lan": func() (string, error) { return managerAutoTCP("172.20.10.2") }, "gimbal-lan": func() (string, error) { return managerAutoTCP("172.20.20.2") }}
	for kind, probe := range jobs {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				begin := managerMono()
				source, err := probe()
				e := managerAutoEvent{Kind: kind, Begin: begin, End: managerMono(), OK: err == nil, Source: source}
				if err != nil {
					e.Error = err.Error()
				}
				if errors.Is(err, errManagerProtocol) {
					r.fail(err.Error())
				}
				if e.OK && !managerAutoSource(kind, source) {
					r.fail("unauthorized packet source: " + kind + " " + source)
				}
				r.add(e)
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		}()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		var stream *managerStream
		session := 0
		defer func() {
			if stream != nil {
				stream.c.Close()
			}
		}()
		for {
			r.mu.Lock()
			wanted := r.streamSession
			r.mu.Unlock()
			if wanted != session {
				if stream != nil {
					stream.c.Close()
				}
				stream = nil
				session = wanted
			}
			begin := managerMono()
			var source string
			var err error
			if stream == nil {
				var c net.Conn
				c, err = net.DialTimeout("tcp4", m3Target+":9192", 400*time.Millisecond)
				if err == nil {
					stream = &managerStream{c: c, reader: bufio.NewReader(c)}
				}
			}
			if stream != nil {
				source, err = stream.exchange()
			}
			e := managerAutoEvent{Kind: "tcp-existing", Begin: begin, End: managerMono(), OK: err == nil, Source: source, Session: session}
			if stream != nil {
				e.Sent = stream.sentAt
			}
			if err != nil {
				e.Error = err.Error()
			}
			if errors.Is(err, errManagerProtocol) {
				r.fail(err.Error())
			}
			if e.OK && !managerAutoSource(e.Kind, source) {
				r.fail("unauthorized existing TCP source: " + source)
			}
			r.add(e)
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	for target, path := range logs {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			offset := 0
			for {
				f, err := os.Open(path)
				if err != nil {
					r.fail(err.Error())
					return
				}
				stat, err := f.Stat()
				if err != nil || stat.Size() > 32*1024*1024 || stat.Size() < int64(offset) {
					f.Close()
					r.fail("application log capacity or truncation")
					return
				}
				b := make([]byte, 256*1024)
				n, err := f.ReadAt(b, int64(offset))
				f.Close()
				if err != nil && err != io.EOF {
					r.fail(err.Error())
					return
				}
				rest := b[:n]
				if n == len(b) && !bytes.Contains(rest, []byte{'\n'}) {
					r.fail("oversized application log record")
					return
				}

				for {
					line, tail, ok := bytes.Cut(rest, []byte{'\n'})
					if !ok {
						break
					}
					offset += len(line) + 1
					rest = tail
					if !bytes.HasPrefix(line, []byte("{")) {
						r.mu.Lock()
						r.warnings++
						r.mu.Unlock()
						continue
					}
					var v relayapply.TargetReconcileResult
					if json.Unmarshal(line, &v) != nil || v.SchemaVersion != 1 {
						r.fail("invalid application cycle JSON")
						return
					}
					if v.Diagnostics == nil || !v.Diagnostics.MonotonicAvailable || v.Diagnostics.CheckpointsDropped {
						r.fail("missing monotonic application evidence")
						return
					}
					row := managerAutoCycle{Observed: managerMono(), Target: target, Applied: v.Applied, Guarded: v.Application.Guarded, Path: v.Selection.DesiredPathID, Reason: v.Selection.Reason, ApplicationReason: v.Application.Reason, Generation: v.Selection.Generation, Candidates: v.Selection.Candidates, Diagnostics: v.Diagnostics}
					r.mu.Lock()
					if len(r.cycles) >= 3000 {
						r.failure = "cycle trace capacity exceeded"
						r.mu.Unlock()
						return
					}
					r.cycles = append(r.cycles, row)
					r.mu.Unlock()
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}()
	}
	return r
}
func managerAutoSource(kind, source string) bool {
	switch kind {
	case "rf-lan":
		return source == "172.20.10.1"
	case "gimbal-lan":
		return source == "172.20.20.1"
	case "independent-app":
		return source == "198.18.0.12"
	}
	return source == "198.18.0.11" || source == "198.18.0.12"
}

func managerTimeline(packets []managerAutoEvent, cycles []managerAutoCycle, previous, desired, source string, begin int64) map[string]int64 {
	var detected, decided, applied, firstSuccess, lastBefore, firstFailure int64
	for _, c := range cycles {
		if c.Target != "app" || c.Diagnostics == nil || int64(c.Diagnostics.FinishedMono) < begin {
			continue
		}
		for _, candidate := range c.Candidates {
			if candidate.PathID == previous && candidate.State != "reachable" && detected == 0 {
				for _, m := range c.Diagnostics.Checkpoints {
					if m.Name == "observation_complete" && int64(m.At) >= begin {
						detected = int64(m.At)
					}
				}
			}
		}
		if c.Path != desired || c.Applied != (desired != "") {
			continue
		}
		for _, m := range c.Diagnostics.Checkpoints {
			if int64(m.At) < begin {
				continue
			}
			if m.Name == "decision_complete" && decided == 0 {
				decided = int64(m.At)
			}
			if (m.Name == "target_routes_applied" || desired == "" && m.Name == "target_routes_blocked") && applied == 0 {
				applied = int64(m.At)
			}
		}
	}
	for _, p := range packets {
		if p.Kind != "tcp-new" {
			continue
		}
		if p.OK && p.End <= begin {
			lastBefore = p.End
		}
		if !p.OK && p.End >= begin && firstFailure == 0 {
			firstFailure = p.End
		}
		if desired != "" && p.OK && p.Source == source && p.Begin >= begin && (applied == 0 || p.Begin >= applied) && firstSuccess == 0 {
			firstSuccess = p.End
		}
	}
	return map[string]int64{"fault_begin": begin, "detection_complete": detected, "decision_complete": decided, "routes_completed": applied, "first_success": firstSuccess, "last_success_before_fault": lastBefore, "first_failure": firstFailure}
}
