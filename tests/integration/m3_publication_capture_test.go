//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func publicationJSON(t *testing.T, at time.Time) []byte {
	t.Helper()
	r := continuityTrace(at)[0]
	r.SchemaVersion = 1
	r.StartedAt, r.FinishedAt = at, at.Add(time.Millisecond)
	r.Selection.TargetID = "private-한글-marker"
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	return append(b, '\n')
}

func TestApplicationContinuityPublicationPipeShutdown(t *testing.T) {
	// Only a local fake ip is executed; no host namespace/network operation.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\n/bin/sleep 1 &\nprintf 'ready\\n'\nexit 0\n"), 0700); err != nil {
		t.Fatal("fixture setup failed")
	}
	t.Setenv("PATH", dir)
	log := filepath.Join(dir, "stdout.log")
	p := startNetworkProcessWithObserver(t, nil, "fixture", log, io.Discard, nil)
	if p.cmd.WaitDelay <= 0 || p.cmd.WaitDelay > 2*time.Second {
		t.Fatal("observer drain is unbounded")
	}
	// Exercise the configured bound without making the test wait two seconds.
	p.cmd.WaitDelay = 20 * time.Millisecond
	deadline := time.Now().Add(time.Second)
	for {
		b, _ := os.ReadFile(log)
		if string(b) == "ready\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture readiness failed")
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	p.stop()
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("producer termination waited for inherited stdout")
	}
}

func TestApplicationContinuityPublicationStreamChunks(t *testing.T) {
	at := time.Unix(1000, 0)
	line := publicationJSON(t, at)
	for _, size := range []int{1, 7, len(line) - 1, len(line), len(line) * 2} {
		s := newPublicationStream()
		clock := at.Add(time.Second)
		s.now = func() time.Time { return clock }
		input := append(append([]byte{}, line...), line...)
		for len(input) > 0 {
			n := min(size, len(input))
			if written, err := s.Write(input[:n]); err != nil || written != n {
				t.Fatal("capture interrupted producer")
			}
			input = input[n:]
		}
		out := s.snapshot()
		if len(out.Records) != 2 || out.PendingBytes != 0 || out.Problem != "" || out.Bytes != int64(2*len(line)) {
			t.Fatal("chunk boundaries changed complete record capture")
		}
		for i, r := range out.Records {
			if r.Record.Index != i || r.SelectedMatches != 1 || !r.ReceivedAt.Equal(clock) {
				t.Fatal("missing receipt sequence/time")
			}
		}
		b, _ := json.Marshal(out)
		if bytes.Contains(b, []byte("private-")) || bytes.Contains(b, []byte("p00")) {
			t.Fatal("raw identifier escaped receipt evidence")
		}
	}
}

func TestApplicationContinuityPublicationStreamPartialAndImmutable(t *testing.T) {
	at := time.Unix(1000, 0)
	s := newPublicationStream()
	clock := at.Add(time.Second)
	s.now = func() time.Time { return clock }
	line := publicationJSON(t, at)
	s.Write(line[:len(line)-1])
	before := s.snapshot()
	if len(before.Records) != 0 || before.PendingBytes != len(line)-1 {
		t.Fatal("JSON without newline was accepted")
	}
	clock = at.Add(2 * time.Second)
	s.Write([]byte{'\n'})
	first := s.snapshot()
	if len(first.Records) != 1 || !first.Records[0].ReceivedAt.Equal(clock) || len(before.Records) != 0 {
		t.Fatal("completion receipt or prior snapshot changed")
	}
	first.Records[0].Record.Candidate.ObservedAt = time.Time{}
	*first.Records[0].Record.Candidate.Age = -1
	after := s.snapshot()
	if after.Records[0].Record.Candidate.ObservedAt.IsZero() || *after.Records[0].Record.Candidate.Age < 0 {
		t.Fatal("snapshot aliases receiver memory")
	}
}

func TestApplicationContinuityPublicationStreamInvalidIsSticky(t *testing.T) {
	for _, tc := range []struct {
		input []byte
		want  string
	}{
		{[]byte("{broken}\n"), "invalid_record"},
		{[]byte("{\"schema_version\":2}\n"), "invalid_record"},
		{bytes.Repeat([]byte{'x'}, applicationLogRecordLimit+1), "record_limit"},
	} {
		s := newPublicationStream()
		s.Write(tc.input)
		s.Write(publicationJSON(t, time.Now()))
		out := s.snapshot()
		if out.Problem != tc.want || len(out.Records) != 0 || out.PendingBytes > applicationLogRecordLimit {
			t.Fatal("invalid input recovered into valid evidence")
		}
	}
	s := newPublicationStream()
	s.input.Bytes = publicationByteLimit
	s.Write([]byte{'x'})
	if s.snapshot().Problem != "stream_limit" {
		t.Fatal("total input not bounded")
	}
	s = newPublicationStream()
	line := publicationJSON(t, time.Now())
	for i := 0; i <= publicationRecordLimit; i++ {
		s.Write(line)
	}
	out := s.snapshot()
	if out.Problem != "record_count_limit" || len(out.Records) != publicationRecordLimit {
		t.Fatal("record history not bounded")
	}
}

func TestApplicationContinuityPublicationStreamConcurrentSnapshot(t *testing.T) {
	s := newPublicationStream()
	line := publicationJSON(t, time.Now())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.Write(line)
		}
	}()
	for i := 0; i < 100; i++ {
		out := s.snapshot()
		if out.Problem != "" || out.PendingBytes != 0 {
			t.Fatal("snapshot raced a complete write")
		}
		for j, r := range out.Records {
			if r.Record.Index != j || r.ReceivedAt.After(out.CapturedAt) {
				t.Fatal("baseline and receipt boundary are inconsistent")
			}
		}
	}
	wg.Wait()
	if len(s.snapshot().Records) != 100 {
		t.Fatal("lost records during snapshot")
	}
}
