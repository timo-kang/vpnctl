package agent

import (
	"testing"

	"vpnctl/internal/config"
	"vpnctl/internal/stunutil"
	"vpnctl/internal/wireguard"
)

func TestDirectKeepalive_SelectsByNAT(t *testing.T) {
	t.Parallel()

	cfg := config.NodeConfig{
		KeepaliveSec:                25,
		DirectKeepaliveSec:          30,
		DirectKeepaliveUnknownSec:   20,
		DirectKeepaliveSymmetricSec: 15,
	}

	if got := directKeepalive(cfg, stunutil.NATTypeSymmetric); got != 15 {
		t.Fatalf("symmetric=%d", got)
	}
	if got := directKeepalive(cfg, stunutil.NATTypeUnknown); got != 20 {
		t.Fatalf("unknown=%d", got)
	}
	if got := directKeepalive(cfg, "cone_or_restricted"); got != 30 {
		t.Fatalf("default=%d", got)
	}
}

func TestPeersEqual(t *testing.T) {
	t.Parallel()

	a := map[string]wireguard.Peer{
		"p1": {PublicKey: "k1", Endpoint: "1.1.1.1:1", AllowedIPs: []string{"10.0.0.1/32"}, KeepaliveSec: 25},
	}
	b := map[string]wireguard.Peer{
		"p1": {PublicKey: "k1", Endpoint: "1.1.1.1:1", AllowedIPs: []string{"10.0.0.1/32"}, KeepaliveSec: 25},
	}
	if !peersEqual(a, b) {
		t.Fatalf("expected equal")
	}
	b["p1"] = wireguard.Peer{PublicKey: "k1", Endpoint: "1.1.1.1:2", AllowedIPs: []string{"10.0.0.1/32"}, KeepaliveSec: 25}
	if peersEqual(a, b) {
		t.Fatalf("expected not equal")
	}
}
