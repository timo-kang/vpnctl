// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relayapply"
	"vpnctl/internal/uplinkapi"
)

func TestGoAndPythonReadAuthenticatedProducer(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	p, err := relayapply.NewUplinkPublisher("app")
	if err != nil {
		t.Fatal(err)
	}
	server, err := uplinkapi.Start(context.Background(), uplinkapi.Options{Directory: dir, AllowedUIDs: []uint32{uint32(os.Geteuid())}}, p)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	state, _ := NewState("app")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Stream(ctx, Options{Directory: dir, ServerUID: uint32(os.Geteuid())}, state) }()
	until := time.Now().Add(2 * time.Second)
	for !state.Current().APIAvailable && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !state.Current().APIAvailable {
		t.Fatal("Go consumer did not receive state")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream cancellation not bounded")
	}
	if state.Current().APIAvailable {
		t.Fatal("closed stream advertised live API")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../../examples/uplink/python")
	pythonCtx, pythonCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pythonCancel()
	cmd := exec.CommandContext(pythonCtx, python, "-B", "-c", `import json,os,sys,threading
sys.path.insert(0,sys.argv[1])
from vpnctl_uplink import State
from transport import stream
s=State('app')
stream(sys.argv[2],os.geteuid(),s,threading.Event(),once=True)
print(json.dumps(s.current()))`, module, dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("Python consumer failed", err, string(output))
	}
	var v View
	if json.Unmarshal(output, &v) != nil || v.Availability != "unknown" || v.Revision != 1 || v.ProducerID != p.Snapshot().ProducerID {
		t.Fatal("Python did not consume actual producer", string(output))
	}
}

const streamHeader = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n"

func streamFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/consumer.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Base json.RawMessage }
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	var value any
	json.Unmarshal(fixture.Base, &value)
	raw, _ := json.Marshal(value)
	return raw
}

func TestStreamRejectsMalformedAndTruncatedInput(t *testing.T) {
	raw := streamFixture(t)
	var many strings.Builder
	for i := 0; i < 512; i++ {
		fmt.Fprintf(&many, "X-%d: x\r\n", i)
	}
	for name, wire := range map[string]string{
		"truncated_record":  streamHeader + string(raw),
		"oversized_record":  streamHeader + strings.Repeat(" ", 4097) + "\n",
		"duplicate_header":  strings.Replace(streamHeader, "Connection:", "CONTENT-TYPE: application/x-ndjson\r\nConnection:", 1),
		"chunked":           strings.Replace(streamHeader, "Connection:", "Transfer-Encoding: chunked\r\nConnection:", 1),
		"content_length":    strings.Replace(streamHeader, "Connection:", "Content-Length: 0\r\nConnection:", 1),
		"oversized_headers": strings.Replace(streamHeader, "Connection:", "X-Fill: "+strings.Repeat("x", 4096)+"\r\nConnection:", 1),
		"many_headers":      strings.Replace(streamHeader, "Connection:", many.String()+"Connection:", 1),
		"bare_lf":           strings.ReplaceAll(streamHeader, "\r\n", "\n"),
		"bad_status":        strings.Replace(streamHeader, "200 OK", "503 Service Unavailable", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if name != "truncated_record" && name != "oversized_record" {
				wire += string(raw) + "\n"
			}
			dir, received := scriptedServer(t, wire, false)
			state, _ := NewState("app")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := Stream(ctx, Options{dir, uint32(os.Geteuid())}, state); err == nil {
				t.Fatal("invalid stream accepted")
			}
			select {
			case <-received:
			default:
				t.Fatal("malformed input did not reach authenticated consumer")
			}
			if v := state.Current(); v.APIAvailable || v.Revision != 0 {
				t.Fatal("incomplete response installed")
			}
		})
	}
}

func TestStreamByteBudget(t *testing.T) {
	record := string(streamFixture(t)) + "\n"
	dir, received := scriptedServer(t, streamHeader+strings.Repeat(record, 256), false)
	state, _ := NewState("app")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := Stream(ctx, Options{dir, uint32(os.Geteuid())}, state); err == nil {
		t.Fatal("unbounded stream accepted")
	}
	select {
	case <-received:
	default:
		t.Fatal("stream fixture not reached")
	}
	if got, want := state.AcceptedFrames(), uint64(64*1024/len(record)); got != want {
		t.Fatal("stream byte budget", got, want)
	}
}

func scriptedServer(t *testing.T, wire string, stall bool) (string, <-chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "uplink.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "uplink.sock"), 0660); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	received := make(chan struct{})
	t.Cleanup(func() { close(done); l.Close() })
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, 512)
		if n, err := c.Read(request); err != nil || n == 0 {
			return
		}
		close(received)
		io.WriteString(c, wire)
		if stall {
			<-done
		}
	}()
	return dir, received
}

func TestStreamCancellationDuringPartialHeader(t *testing.T) {
	dir, received := scriptedServer(t, "HTTP/1.1 200", true)
	state, _ := NewState("app")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Stream(ctx, Options{dir, uint32(os.Geteuid())}, state) }()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("partial header connection not reached")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
}

func TestPythonReferenceContract(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../../examples/uplink/python")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-B", "-m", "unittest", "discover", "-s", module, "-p", "test_*.py")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python reference tests: %v\n%s", err, out)
	}
}
