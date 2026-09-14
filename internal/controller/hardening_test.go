// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/pki"
	"vpnctl/internal/store"
)

func TestRegisterRejectsUnsafeMetadataWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*api.RegisterRequest)
	}{
		{name: "oversized identity", mutate: func(req *api.RegisterRequest) { req.Name = strings.Repeat("n", 256) }},
		{name: "public key config injection", mutate: func(req *api.RegisterRequest) { req.PubKey = "key\n[Peer]" }},
		{name: "endpoint config injection", mutate: func(req *api.RegisterRequest) { req.Endpoint = "host:51820\nAllowedIPs = 0.0.0.0/0" }},
		{name: "public address control character", mutate: func(req *api.RegisterRequest) { req.PublicAddr = "host:51900\rspoof" }},
		{name: "NAT type control character", mutate: func(req *api.RegisterRequest) { req.NATType = "full-cone\tspoof" }},
		{name: "invalid probe port", mutate: func(req *api.RegisterRequest) { req.ProbePort = 65536 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			request := api.RegisterRequest{Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32"}
			tt.mutate(&request)
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			recorder := httptest.NewRecorder()
			s.handleRegister(recorder, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if len(s.reg.Nodes) != 0 {
				t.Fatalf("rejected registration mutated registry: %+v", s.reg.Nodes)
			}
		})
	}
}

func TestRegisterRejectsDuplicatePublicKeyWithoutMutation(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.reg.Nodes = []store.NodeInfo{{
		ID: "node-a", Name: "node-a", PubKey: "shared-key", VPNIP: "10.7.0.2/32",
	}}
	body, err := json.Marshal(api.RegisterRequest{
		Name: "node-b", PubKey: "shared-key", VPNIP: "10.7.0.3/32",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	s.handleRegister(recorder, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(s.reg.Nodes) != 1 || s.reg.Nodes[0].ID != "node-a" {
		t.Fatalf("duplicate-key request mutated registry: %+v", s.reg.Nodes)
	}
}

func TestDecodeJSONRejectsOversizedAndMultipleDocuments(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		wantError string
	}{
		{
			name: "oversized body",
			body: []byte(`{"name":"node-a","pub_key":"pub-a","nat_type":"` +
				strings.Repeat("a", maxRequestBodyBytes) + `"}`),
			wantError: "request body too large",
		},
		{
			name:      "multiple JSON documents",
			body:      []byte(`{"name":"node-a","pub_key":"pub-a"}{"name":"node-b","pub_key":"pub-b"}`),
			wantError: "single JSON object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			recorder := httptest.NewRecorder()
			s.handleRegister(recorder, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(tt.body)))
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), tt.wantError) {
				t.Fatalf("status=%d body=%s, want %q", recorder.Code, recorder.Body.String(), tt.wantError)
			}
			if len(s.reg.Nodes) != 0 {
				t.Fatalf("invalid JSON mutated registry: %+v", s.reg.Nodes)
			}
		})
	}
}

func TestNATProbeRejectsUnsafeMetadataWithoutMutation(t *testing.T) {
	s, err := NewServer(config.ControllerConfig{DataDir: t.TempDir(), VPNCIDR: "10.7.0.0/24"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.reg.Nodes = []store.NodeInfo{{
		ID: "node-a", Name: "node-a", NATType: "restricted", PublicAddr: "198.51.100.1:51900",
	}}
	body, err := json.Marshal(api.NATProbeRequest{
		NodeID: "node-a", NATType: "spoof\nvalue", PublicAddr: "203.0.113.1:51900",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	s.handleNATProbe(recorder, httptest.NewRequest(http.MethodPost, "/nat-probe", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := s.reg.Nodes[0]; got.NATType != "restricted" || got.PublicAddr != "198.51.100.1:51900" {
		t.Fatalf("rejected NAT report mutated registry: %+v", got)
	}
}

func TestNewServerRejectsDuplicateOrUnsafePersistedMetadata(t *testing.T) {
	tests := []struct {
		name  string
		nodes []store.NodeInfo
		want  string
	}{
		{
			name: "duplicate public key",
			nodes: []store.NodeInfo{
				{ID: "node-a", Name: "node-a", PubKey: "shared-key"},
				{ID: "node-b", Name: "node-b", PubKey: "shared-key"},
			},
			want: "public key is assigned",
		},
		{
			name:  "unsafe endpoint",
			nodes: []store.NodeInfo{{ID: "node-a", Name: "node-a", Endpoint: "host:1\n[Peer]"}},
			want:  "control characters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := store.SaveRegistry(filepath.Join(dir, "registry.yaml"), &store.Registry{Nodes: tt.nodes}); err != nil {
				t.Fatalf("SaveRegistry: %v", err)
			}
			_, err := NewServer(config.ControllerConfig{DataDir: dir})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewServer error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestBootstrapObservesExternalTokenCreateAndRepeatedRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := NewServer(config.ControllerConfig{
		DataDir: dir,
		VPNCIDR: "10.7.0.0/24",
		Listen:  "127.0.0.1:8443",
		PKI: &config.PKIConfig{
			CAExpiry: "24h", ServerExpiry: "24h", ClientExpiry: "24h",
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	initialToken, err := s.InitPKI()
	if err != nil {
		t.Fatalf("InitPKI: %v", err)
	}
	external, err := pki.OpenTokenStore(filepath.Join(dir, "pki", "bootstrap-tokens.json"))
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	newToken, err := external.Create()
	if err != nil {
		t.Fatalf("external Create: %v", err)
	}
	if err := external.Revoke(initialToken); err != nil {
		t.Fatalf("external Revoke: %v", err)
	}
	csr, _, err := pki.GenerateCSR("ignored-csr-identity")
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	makeBody := func(token string) []byte {
		body, err := json.Marshal(api.BootstrapRequest{Token: token, Name: "node-a", CSR: string(csr)})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return body
	}
	for attempt := 0; attempt < 50; attempt++ {
		recorder := httptest.NewRecorder()
		s.handleBootstrap(recorder, httptest.NewRequest(http.MethodPost, "/bootstrap", bytes.NewReader(makeBody(initialToken))))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("revoked token attempt %d status=%d body=%s", attempt, recorder.Code, recorder.Body.String())
		}
	}
	if len(s.reg.Nodes) != 0 {
		t.Fatalf("revoked token attempts mutated registry: %+v", s.reg.Nodes)
	}

	recorder := httptest.NewRecorder()
	s.handleBootstrap(recorder, httptest.NewRequest(http.MethodPost, "/bootstrap", bytes.NewReader(makeBody(newToken))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("externally created token status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(s.reg.Nodes) != 1 || s.reg.Nodes[0].ID != "node-a" {
		t.Fatalf("valid external token registration=%+v", s.reg.Nodes)
	}
}
