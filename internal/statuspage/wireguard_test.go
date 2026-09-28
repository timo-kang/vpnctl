package statuspage

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWireGuardOutputEscapesIdentityAndKeepsExactCounter(t *testing.T) {
	w := httptest.NewRecorder()
	Handler(func() Data {
		return Data{Nodes: []NodeStatus{{Name: "robot", WireGuard: []string{"<script> RX/TX(bytes)=9007199254740993/0 hs=never"}}}}
	})(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	if !strings.Contains(body, "WireGuard transport") || !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "9007199254740993/0") || strings.Contains(body, "<script>") {
		t.Fatal(body)
	}
}
