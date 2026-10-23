//go:build integration

package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateTraceSummaryPreservesNanoseconds(t *testing.T) {
	// Real retained evidence exposed float64 rounding of this timestamp.
	input := []byte(`{"start_clock":{"wall_ns":1792733623262739326},"events":[{},{}],"complete":false,"errors":["lost"]}`)
	meta, err := privateTraceSummary(input)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"wall_ns":1792733623262739326`) || !strings.Contains(string(b), `"retained_events":2`) || strings.Contains(string(b), `"events"`) {
		t.Fatalf("evidence precision or event boundary changed: %s", b)
	}
	if meta["complete"] != false || len(meta["errors"].([]any)) != 1 {
		t.Fatal("failure evidence disappeared")
	}
	if _, err := privateTraceSummary([]byte(`null`)); err == nil {
		t.Fatal("missing metadata accepted")
	}
}
