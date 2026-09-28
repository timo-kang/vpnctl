// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpnctl/internal/history"
)

func TestClient_ErrorIncludesBody(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"nope"}`))
	}))
	defer s.Close()

	c := NewClient(s.URL)
	_, err := c.Register(context.Background(), RegisterRequest{Name: "n", PubKey: "k"})
	if err == nil {
		t.Fatalf("expected error")
	}
	got := err.Error()
	if got == "" || got[len(got)-1] == '\n' {
		t.Fatalf("unexpected error string: %q", got)
	}
	if want := "400"; !strings.Contains(got, want) {
		t.Fatalf("error missing status: %q", got)
	}
	if want := `"error":"nope"`; !strings.Contains(got, want) {
		t.Fatalf("error missing body: %q", got)
	}
}

func TestFleetHistoryV3RequiresMetadataAndPreservesPageFilters(t *testing.T) {
	for _, missing := range []string{"", "tiering", "storage"} {
		t.Run(missing, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("source") != "agent-direct" || q.Get("cursor") != "opaque-page" || q.Get("node_id") != "robot" || q.Get("window") != "7d" || q.Get("bucket") != "1h" {
					t.Error("page filters changed", q)
				}
				resp := FleetHistoryResponse{SchemaVersion: 3, Tiering: &history.PageInfo{NextCursor: "next"}, Storage: &history.TieredStats{}, Nodes: []FleetNodeHistory{}}
				if missing == "tiering" {
					resp.Tiering = nil
				}
				if missing == "storage" {
					resp.Storage = nil
				}
				json.NewEncoder(w).Encode(resp)
			}))
			defer s.Close()
			resp, err := NewClient(s.URL).FleetHistoryPage(context.Background(), "7d", "robot", "1h", "agent-direct", "opaque-page")
			if missing == "" {
				if err != nil || resp.Tiering.NextCursor != "next" {
					t.Fatal(resp, err)
				}
			} else if err == nil {
				t.Fatal("incomplete v3 accepted")
			}
		})
	}
}

func TestFleetClientRejectsUnversionedAndUnsupportedQuality(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"schema_version":%d,"nodes":[]}`, version)
			}))
			defer s.Close()
			c := NewClient(s.URL)
			_, statusErr := c.FleetStatus(context.Background())
			_, historyErr := c.FleetHistory(context.Background(), "24h")
			if version == 2 {
				if statusErr != nil || historyErr != nil {
					t.Fatal(statusErr, historyErr)
				}
			} else if statusErr == nil || historyErr == nil {
				t.Fatal("unsupported fleet values accepted", version)
			}
		})
	}
}
