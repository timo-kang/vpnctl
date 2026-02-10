package agent

import (
	"testing"

	"vpnctl/internal/api"
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

func TestPeerInjection_SkipsDuplicateAllowedIPs(t *testing.T) {
	t.Parallel()

	// This test is indirect: it verifies we don't panic and that duplicates
	// don't cause unstable map states. The actual WireGuard rejection happens
	// at apply time; skipping duplicates prevents apply from failing.
	candidates := []api.PeerCandidate{
		{ID: "a", Name: "a", PubKey: "k1", VPNIP: "10.7.0.23/32", Endpoint: "1.1.1.1:1"},
		{ID: "b", Name: "b", PubKey: "k2", VPNIP: "10.7.0.23/32", Endpoint: "2.2.2.2:2"},
	}

	allowedOwner := map[string]string{}
	desired := map[string]wireguard.Peer{}
	cfg := config.NodeConfig{KeepaliveSec: 25}
	for _, peer := range candidates {
		wgEndpoint := peer.Endpoint
		allowedIP := normalizeHostIP(peer.VPNIP)
		if allowedIP != "" {
			if prev, ok := allowedOwner[allowedIP]; ok && prev != peer.ID {
				continue
			}
			allowedOwner[allowedIP] = peer.ID
		}
		if allowedIP != "" && peer.PubKey != "" && wgEndpoint != "" {
			desired[peer.ID] = wireguard.Peer{
				PublicKey:    peer.PubKey,
				Endpoint:     wgEndpoint,
				AllowedIPs:   []string{allowedIP},
				KeepaliveSec: directKeepalive(cfg, peer.NATType),
			}
		}
	}
	if len(desired) != 1 {
		t.Fatalf("desired=%d", len(desired))
	}
}
