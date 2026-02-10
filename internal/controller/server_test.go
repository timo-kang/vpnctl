package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/execx"
	"vpnctl/internal/store"
	"vpnctl/internal/wireguard"
)

func TestHandleRegister_AllocationError_DoesNotHoldLock(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:     tmp,
		VPNCIDR:     "not-a-cidr",
		WGApply:     false,
		Listen:      "127.0.0.1:0",
		WGPort:      51820,
		WGInterface: "wg0",
	}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	body, _ := json.Marshal(api.RegisterRequest{Name: "node-a", PubKey: "pub", VPNIP: ""})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleRegister(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	// If handleRegister returned while holding the lock, this would deadlock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		body2, _ := json.Marshal(api.RegisterRequest{Name: "node-a", PubKey: "pub", VPNIP: "10.7.0.2/32"})
		req2 := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body2))
		rec2 := httptest.NewRecorder()
		s.handleRegister(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Errorf("second status=%d body=%s", rec2.Code, rec2.Body.String())
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRegister likely deadlocked (registry lock not released)")
	}

	// Registry persisted.
	regPath := filepath.Join(tmp, "registry.yaml")
	reg, err := store.LoadRegistry(regPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(reg.Nodes) != 1 {
		t.Fatalf("nodes=%d", len(reg.Nodes))
	}
	if reg.Nodes[0].VPNIP != "10.7.0.2/32" {
		t.Fatalf("vpn_ip=%q", reg.Nodes[0].VPNIP)
	}
}

func TestAllocateVPNIP_Unique(t *testing.T) {
	t.Parallel()

	reg := &store.Registry{
		Nodes: []store.NodeInfo{
			{Name: "a", VPNIP: "10.7.0.2/32"},
			{Name: "b", VPNIP: "10.7.0.3/32"},
		},
	}

	ip, err := allocateVPNIP("10.7.0.0/24", reg)
	if err != nil {
		t.Fatalf("allocateVPNIP: %v", err)
	}
	if ip == "10.7.0.2/32" || ip == "10.7.0.3/32" {
		t.Fatalf("allocated used ip: %s", ip)
	}
}

func TestAllocateVPNIP_RejectsHugeCIDR(t *testing.T) {
	t.Parallel()

	_, err := allocateVPNIP("10.0.0.0/8", &store.Registry{})
	if err == nil {
		t.Fatalf("expected error")
	}
}

type fakeRunner struct {
	out map[string]string
}

func (f *fakeRunner) Run(name string, args ...string) error { return nil }

func (f *fakeRunner) Output(name string, args ...string) (string, error) {
	k := name + " " + strings.Join(args, " ")
	if f.out == nil {
		return "", nil
	}
	return f.out[k], nil
}

var _ execx.Runner = (*fakeRunner)(nil)

func TestHandleCandidates_FillsObservedEndpointFromWgDump(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfg := config.ControllerConfig{
		DataDir:     tmp,
		Listen:      "127.0.0.1:0",
		WGInterface: "wg0",
		VPNCIDR:     "10.7.0.0/24",
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	wgDump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"pub-b\t(psk)\t39.1.2.3:51820\t10.7.0.12/32\t0\t0\t0\toff\n"
	s.wg = wireguard.NewManager(&fakeRunner{
		out: map[string]string{
			"wg show wg0 dump": wgDump,
		},
	})

	s.reg.Nodes = []store.NodeInfo{
		{ID: "node-a", Name: "node-a", PubKey: "pub-a", VPNIP: "10.7.0.2/32"},
		{ID: "node-b", Name: "node-b", PubKey: "pub-b", VPNIP: "10.7.0.12/32"},
	}

	req := httptest.NewRequest(http.MethodGet, "/candidates?node_id=node-a", nil)
	rec := httptest.NewRecorder()
	s.handleCandidates(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp api.CandidatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("peers=%d", len(resp.Peers))
	}
	if resp.Peers[0].Name != "node-b" {
		t.Fatalf("peer=%+v", resp.Peers[0])
	}
	if resp.Peers[0].Endpoint != "39.1.2.3:51820" {
		t.Fatalf("endpoint=%q", resp.Peers[0].Endpoint)
	}
}

func TestP2PReadyLocked_MutualSuccess(t *testing.T) {
	t.Parallel()

	s := &Server{
		directOK: map[string]map[string]time.Time{
			"a": {"b": time.Now().UTC()},
			"b": {"a": time.Now().UTC()},
		},
	}
	if !s.p2pReadyLocked("a", "b") {
		t.Fatalf("expected ready")
	}
}
