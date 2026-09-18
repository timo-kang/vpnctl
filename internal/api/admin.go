// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"vpnctl/internal/pki"
)

// AdminSocketPath is local to the controller's data directory, never its TCP API.
func AdminSocketPath(dataDir string) string { return filepath.Join(dataDir, "run", "admin.sock") }

type AdminRequest struct {
	RequestID   string `json:"request_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Operation   string `json:"operation"`
	NodeID      string `json:"node_id,omitempty"`
	Token       string `json:"token,omitempty"`
	TTL         string `json:"ttl,omitempty"`
	SingleUse   bool   `json:"single_use,omitempty"`
}

type AdminResponse struct {
	RequestID   string               `json:"request_id,omitempty"`
	TokenRecord *pki.TokenRecord     `json:"token_record,omitempty"`
	PKI         *pki.AuthorityStatus `json:"pki,omitempty"`
	Backup      []byte               `json:"backup,omitempty"`
	Token       string               `json:"token,omitempty"`
	Tokens      []pki.TokenRecord    `json:"tokens,omitempty"`
}

// Admin calls controller-owned IPC. There is deliberately no direct-file fallback.
func Admin(ctx context.Context, dataDir string, request AdminRequest) (AdminResponse, error) {
	// Generate before sending so even a lost response has a recoverable key.
	if request.Operation == "token.create" && request.RequestID == "" {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return AdminResponse{}, err
		}
		request.RequestID = hex.EncodeToString(random[:])
	}
	socket := AdminSocketPath(dataDir)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &Client{baseURL: "http://controller", http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	response := AdminResponse{RequestID: request.RequestID}
	if err := client.postJSON(ctx, "/admin", request, &response); err != nil {
		if request.Operation == "token.create" {
			return response, fmt.Errorf("controller admin IPC (%s), token request_id=%s (query token result or retry create with the same ID and options): %w", socket, request.RequestID, err)
		}
		return response, fmt.Errorf("controller admin IPC (%s; controller must be running): %w", socket, err)
	}
	return response, nil
}
