// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
