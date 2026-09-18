// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/history"
)

func TestEventAPIAuthenticationAndTimeline(t *testing.T) {
	s := newIdentityTestServer(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	req := api.EventRequest{NodeID: "node-a", Event: history.Event{ID: "cert-1", Timestamp: now, Kind: "certificate", Source: "agent", Severity: "warning", Validity: "observed", Message: "renewal_due"}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.requireClientCert(s.handleEvent)(rec, requestWithNodeCertificate(t, "POST", "/events", body, "node-a"))
	if rec.Code != 204 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	bad := req
	bad.NodeID = "node-b"
	body, _ = json.Marshal(bad)
	rec = httptest.NewRecorder()
	s.requireClientCert(s.handleEvent)(rec, requestWithNodeCertificate(t, "POST", "/events", body, "node-a"))
	if rec.Code != 403 {
		t.Fatal("cross-node event accepted", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.handleAuthorizedEvents(rec, requestWithNodeCertificate(t, "GET", "/fleet/events?node_id=node-a", nil, "node-a"))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var events history.EventHistory
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.Events[0].Kind != "certificate" {
		t.Fatalf("events=%+v", events)
	}
	rec = httptest.NewRecorder()
	s.handleAuthorizedAlerts(rec, requestWithNodeCertificate(t, "GET", "/fleet/alerts?node_id=node-a", nil, "node-a"))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
