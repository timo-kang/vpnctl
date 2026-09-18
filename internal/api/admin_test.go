// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnctl/internal/pki"
)

func TestAdminRetainsCreateIDAfterResponseLoss(t *testing.T) {
	dir, err := os.MkdirTemp("", "admin-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := AdminSocketPath(dir)
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan AdminRequest, 2)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AdminRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		received <- req
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	})}
	go server.Serve(listener)
	defer server.Close()
	for _, id := range []string{"", "saved-request"} {
		response, err := Admin(context.Background(), dir, AdminRequest{Operation: "token.create", RequestID: id})
		if err == nil {
			t.Fatal("lost response reported success")
		}
		request := <-received
		if pki.ValidateRequestID(request.RequestID) != nil || response.RequestID != request.RequestID || !strings.Contains(err.Error(), request.RequestID) {
			t.Fatal("recovery request ID lost", err)
		}
		if id != "" && response.RequestID != id {
			t.Fatal("supplied retry ID replaced")
		}
	}
}
