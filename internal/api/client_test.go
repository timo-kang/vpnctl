package api

import (
	"context"
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
