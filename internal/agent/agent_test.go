// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/stunutil"
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

func TestDirectCandidatesRejectDuplicateDestinations(t *testing.T) {
	cfg, p := directFixture()
	other := p
	other.ID = "other"
	if _, err := directCandidates(cfg, directSnapshot{peers: []api.PeerCandidate{p, other}}); err == nil {
		t.Fatal("duplicate admitted")
	}
}
