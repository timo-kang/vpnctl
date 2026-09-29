// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"vpnctl/internal/relaycatalog"
)

func TestRelayCatalogRejectsMalformedResponses(t *testing.T) {
	v := relaycatalog.View{ControllerID: strings.Repeat("a", 32), Generation: 1, NodeID: "robot", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Spec: relaycatalog.Spec{SchemaVersion: 1, PoolCIDR: "10.78.0.0/24"}}
	raw, _ := json.Marshal(v)
	for name, response := range map[string]string{
		"valid": string(raw), "oversize": strings.Repeat(" ", relaycatalog.MaxDocumentBytes+1),
		"trailing": string(raw) + "{}", "unknown": strings.Replace(string(raw), `"node_id":`, `"surprise":1,"node_id":`, 1),
		"foreign": strings.Replace(string(raw), `"robot"`, `"other"`, 1), "schema": strings.Replace(string(raw), `"schema_version":1`, `"schema_version":9`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(response)) }))
			defer server.Close()
			client := NewClient(server.URL)
			_, e := client.RelayCatalog(context.Background(), "robot")
			if (e == nil) != (name == "valid") {
				t.Fatalf("%s: %v", name, e)
			}
			if _, e = client.BindRelayPath(context.Background(), relaycatalog.BindRequest{ControllerID: v.ControllerID, ExpectedGeneration: 1, NodeID: "robot", PathID: "missing", PublicKey: "key"}); e == nil {
				t.Fatal("response lacking binding accepted")
			}
		})
	}
}
