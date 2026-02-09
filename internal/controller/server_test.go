package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/store"
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
