// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/relaycatalog"
)

func TestRelayDeploymentRejectsMalformedResponses(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 1
	key, _ := ecdh.X25519().NewPrivateKey(seed)
	v := relaycatalog.DeploymentView{SchemaVersion: 1, ControllerID: strings.Repeat("a", 32), Generation: 1, PrincipalID: "agent", RelayID: "r", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Spec: relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24", Relays: []relaycatalog.Relay{{ID: "r", PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: "192.0.2.1:51820"}}}}}}
	raw, _ := json.Marshal(v)
	for name, response := range map[string]string{
		"valid": string(raw), "oversize": strings.Repeat(" ", relaycatalog.MaxDocumentBytes+1),
		"trailing": string(raw) + "{}", "unknown": strings.Replace(string(raw), `"principal_id":`, `"private_key":"secret","principal_id":`, 1),
		"foreign": strings.Replace(string(raw), `"agent"`, `"other"`, 1), "null": "null",
	} {
		t.Run(name, func(t *testing.T) {
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/relay-deployment" || r.URL.Query().Get("relay_id") != "r" || r.URL.Query().Get("principal_id") != "" {
					t.Error("unexpected authorization query")
				}
				w.Write([]byte(response))
			}))
			defer h.Close()
			got, e := NewClient(h.URL).RelayDeployment(context.Background(), "agent", "r")
			if (e == nil) != (name == "valid") {
				t.Fatal(name, e)
			}
			if e != nil && got.ControllerID != "" {
				t.Fatal("invalid response returned usable approval")
			}
		})
	}
}
