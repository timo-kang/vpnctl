// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"errors"
	"strings"
	"testing"
)

const desiredSetConf = "[Interface]\nPrivateKey = test-key\nListenPort = 51820\n\n[Peer]\nPublicKey = peer-a\nAllowedIPs = 10.77.0.2/32, 10.77.0.3/32\n"
const currentSetConf = "[Interface]\nListenPort = 51820\nPrivateKey = test-key\n[Peer]\nEndpoint = 192.0.2.2:50123\nAllowedIPs = 10.77.0.3/32,10.77.0.2/32\nPublicKey = peer-a\n"

func TestSameSetConfPreservesLearnedEndpointButDetectsDrift(t *testing.T) {
	if !sameSetConf(desiredSetConf, currentSetConf) {
		t.Fatal("unchanged peers should preserve learned NAT endpoints and CIDR order")
	}
	cases := map[string]string{
		"removed peer":    "[Interface]\nPrivateKey = test-key\nListenPort = 51820\n",
		"extra peer":      currentSetConf + "[Peer]\nPublicKey = unauthorized\nAllowedIPs = 10.77.0.4/32\n",
		"changed prefix":  strings.ReplaceAll(currentSetConf, "10.77.0.2/32", "10.77.0.2/31"),
		"wrong key":       strings.ReplaceAll(currentSetConf, "test-key", "different-key"),
		"wrong port":      strings.ReplaceAll(currentSetConf, "51820", "51821"),
		"preshared key":   currentSetConf + "PresharedKey = unexpected-key\n",
		"keepalive":       currentSetConf + "PersistentKeepalive = 25\n",
		"duplicate field": currentSetConf + "PublicKey = peer-b\n",
		"duplicate peer":  currentSetConf + "[Peer]\nPublicKey = peer-a\n",
		"malformed":       "invalid output",
	}
	for name, current := range cases {
		t.Run(name, func(t *testing.T) {
			if sameSetConf(desiredSetConf, current) {
				t.Fatal("runtime drift must be reconciled")
			}
		})
	}
	configured := desiredSetConf + "Endpoint = 192.0.2.3:51820\n"
	if sameSetConf(configured, currentSetConf) {
		t.Fatal("explicit endpoints must not be treated as learned")
	}
}

type confRunner struct {
	current string
	readErr error
	writes  int
}

func (r *confRunner) Output(name string, args ...string) (string, error) { return r.current, r.readErr }
func (r *confRunner) Run(name string, args ...string) error              { r.writes++; return nil }

func TestSyncConfAlwaysInspectsRuntimeAndRepairsChanges(t *testing.T) {
	r := &confRunner{current: currentSetConf}
	m := NewManager(r)
	for i := 0; i < 100; i++ {
		if err := m.syncConf("wg0", desiredSetConf); err != nil {
			t.Fatal(err)
		}
	}
	if r.writes != 0 {
		t.Fatal("heartbeat reapplied an unchanged peer configuration")
	}
	r.current = strings.ReplaceAll(currentSetConf, "peer-a", "unexpected-peer")
	if err := m.syncConf("wg0", desiredSetConf); err != nil {
		t.Fatal(err)
	}
	if r.writes != 1 {
		t.Fatal("external change was hidden by a successful-apply cache")
	}
	r.current = currentSetConf
	r.readErr = errors.New("device was recreated")
	if err := m.syncConf("wg0", desiredSetConf); err != nil {
		t.Fatal(err)
	}
	if r.writes != 2 {
		t.Fatal("failed inspection must fall back to reconciliation")
	}
}

func TestSyncConfPreservesUnspecifiedKernelListenPort(t *testing.T) {
	desired := strings.ReplaceAll(desiredSetConf, "ListenPort = 51820\n", "")
	r := &confRunner{current: strings.ReplaceAll(currentSetConf, "51820", "43721")}
	m := NewManager(r)
	for i := 0; i < 100; i++ {
		if err := m.syncConf("wg0", desired); err != nil {
			t.Fatal(err)
		}
	}
	if r.writes != 0 {
		t.Fatalf("dynamic listen port caused %d unnecessary WG applies", r.writes)
	}
	for _, changed := range []string{
		strings.ReplaceAll(r.current, "43721", "invalid"),
		strings.ReplaceAll(r.current, "43721", "0"),
		strings.ReplaceAll(r.current, "43721", "65536"),
		strings.ReplaceAll(r.current, "test-key", "unexpected-key"),
		strings.ReplaceAll(r.current, "10.77.0.2/32", "10.77.0.99/32"),
	} {
		if sameSetConf(desired, changed) {
			t.Fatal("dynamic port hid invalid runtime state")
		}
	}
	if sameSetConf(desiredSetConf, r.current) {
		t.Fatal("explicit port drift ignored")
	}
}
