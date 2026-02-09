package wireguard

import (
	"strings"
	"testing"

	"vpnctl/internal/config"
)

func TestRenderNode_IncludesMTUAndListenPort(t *testing.T) {
	t.Parallel()

	cfg := config.NodeConfig{
		WGPrivateKey:    "priv",
		VPNIP:           "10.7.0.2/32",
		MTU:             1280,
		WGListenPort:    51820,
		ServerPublicKey: "serverpub",
		ServerEndpoint:  "1.2.3.4:51820",
		ServerAllowedIPs: []string{
			"10.7.0.0/24",
		},
		ServerKeepaliveSec: 25,
	}

	out, err := RenderNode(cfg)
	if err != nil {
		t.Fatalf("RenderNode: %v", err)
	}
	if !strings.Contains(out, "MTU = 1280") {
		t.Fatalf("missing MTU: %s", out)
	}
	if !strings.Contains(out, "ListenPort = 51820") {
		t.Fatalf("missing ListenPort: %s", out)
	}
	if !strings.Contains(out, "PersistentKeepalive = 25") {
		t.Fatalf("missing keepalive: %s", out)
	}
}

func TestRenderSetConf_RendersPeers(t *testing.T) {
	t.Parallel()

	cfg := config.NodeConfig{
		WGPrivateKey:     "priv",
		ServerPublicKey:  "serverpub",
		ServerEndpoint:   "1.2.3.4:51820",
		ServerAllowedIPs: []string{"10.7.0.0/24"},
	}

	out, err := RenderSetConf(cfg, []Peer{
		{PublicKey: "p1", Endpoint: "5.6.7.8:51820", AllowedIPs: []string{"10.7.0.12/32"}, KeepaliveSec: 15},
	})
	if err != nil {
		t.Fatalf("RenderSetConf: %v", err)
	}
	if !strings.Contains(out, "PublicKey = p1") || !strings.Contains(out, "Endpoint = 5.6.7.8:51820") {
		t.Fatalf("missing peer: %s", out)
	}
}
