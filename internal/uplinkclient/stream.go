// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"vpnctl/internal/uplinkapi"
)

type Options struct {
	Directory string
	ServerUID uint32
}

var errTransport = errors.New("invalid or oversized uplink stream")

// Stream consumes one authenticated, bounded connection. Its caller owns retry
// policy. Losing this connection never instructs an application to close its
// payload connection. There is no event queue: State retains only the latest.
func Stream(ctx context.Context, opts Options, state *State) error {
	if state == nil {
		return errors.New("uplink state required")
	}
	epoch := state.Begin()
	defer state.Disconnect(epoch)
	if epoch == 0 {
		return errors.New("uplink stream epoch exhausted")
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	c, err := uplinkapi.Dial(ctx, opts.Directory, opts.ServerUID)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	path := "/v1/events"
	if cursor := state.Cursor(); cursor != "" {
		path += "?after=" + url.QueryEscape(cursor)
	}
	if err = c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if _, err = io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: uplink\r\n\r\n"); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(c, 4097)
	if err = c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if err = readHeader(reader); err != nil {
		return err
	}
	remaining := 64 * 1024
	for remaining > 0 {
		// Server heartbeats are five seconds apart. This is a transport watchdog,
		// not the validity budget of any observation or an application SLO.
		if err = c.SetReadDeadline(time.Now().Add(6 * time.Second)); err != nil {
			return err
		}
		line, e := reader.ReadSlice('\n')
		if e != nil {
			return e // An EOF fragment is never a complete NDJSON record.
		}
		if len(line) > remaining || len(line) > 4097 {
			return errTransport
		}
		remaining -= len(line)
		if err = state.Accept(epoch, line[:len(line)-1]); err != nil {
			return err
		}
	}
	return errTransport
}

// The reference protocol has close-delimited NDJSON, with no HTTP chunking.
// Bound headers before parsing them, including many short fields and slow input.
func readHeader(r *bufio.Reader) error {
	remaining := 4096
	fields := make(map[string]string)
	for first := true; ; first = false {
		line, err := r.ReadSlice('\n')
		if err != nil || len(line) > remaining || !strings.HasSuffix(string(line), "\r\n") {
			return errTransport
		}
		remaining -= len(line)
		s := string(line[:len(line)-2])
		if first {
			if s != "HTTP/1.1 200 OK" {
				return errTransport
			}
			continue
		}
		if s == "" {
			break
		}
		key, value, ok := strings.Cut(s, ":")
		if !ok || key == "" {
			return errTransport
		}
		for _, b := range key {
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", b)) {
				return errTransport
			}
		}
		for _, b := range value {
			if b != '\t' && (b < 32 || b > 126) {
				return errTransport
			}
		}
		key = strings.ToLower(key)
		if _, duplicate := fields[key]; duplicate {
			return errTransport
		}
		fields[key] = strings.Trim(value, " \t")
	}
	_, length := fields["content-length"]
	_, chunked := fields["transfer-encoding"]
	if length || chunked || fields["content-type"] != "application/x-ndjson" || fields["connection"] != "close" {
		return errTransport
	}
	return nil
}
