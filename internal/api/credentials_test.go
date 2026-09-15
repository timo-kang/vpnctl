// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPKICredentialFailureNeverFallsBackToPlainHTTP(t *testing.T) {
	var requests atomic.Int32
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.Write([]byte(`{"nodes":[]}`)) }))
	defer h.Close()
	dir := t.TempDir()
	client := NewCredentialClient(h.URL, dir)
	defer client.CloseIdleConnections()
	if _, err := client.FleetStatus(context.Background()); err == nil {
		t.Fatal("missing PKI accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FleetStatus(context.Background()); err == nil {
		t.Fatal("corrupt PKI accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("PKI error leaked a plain HTTP request")
	}
}
