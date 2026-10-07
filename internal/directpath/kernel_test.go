// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fixtureRunner struct {
	dump  string
	calls []string
	argv  [][]string
}

func (r *fixtureRunner) RunContext(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.argv = append(r.argv, append([]string{name}, args...))
	return nil
}
func (r *fixtureRunner) OutputContext(_ context.Context, name string, args ...string) (string, error) {
	if name == "ip" {
		return `[{"ifindex":7,"ifalias":"external owner","linkinfo":{"info_kind":"wireguard"}}]`, nil
	}
	return r.dump, nil
}
func TestKernelReadsDisabledKeepaliveAndOnlyMutatesNamedPeer(t *testing.T) {
	for _, keepalive := range []string{"off", "0", "25", "invalid", "-1", "65536"} {
		t.Run(keepalive, func(t *testing.T) {
			runner := &fixtureRunner{dump: fmt.Sprintf("secret-private-key %s 51820 off\n%s (none) 192.0.2.3:51820 10.7.0.3/32 1 50 60 %s", key(1), key(3), keepalive)}
			k := kernel{"wg0", "10.7.0.2", runner}
			s, err := k.Snapshot(context.Background())
			if keepalive == "invalid" || keepalive == "-1" || keepalive == "65536" {
				if err == nil {
					t.Fatal("invalid keepalive accepted")
				}
				return
			}
			if err != nil || s.Identity.PublicKey != key(1) || s.Peers[key(3)].PSK {
				t.Fatal(s, err)
			}
			c := Candidate{Key: key(3), Endpoint: "192.0.2.3:51820", Address: "10.7.0.3", Keepalive: 25}
			if err := k.Add(context.Background(), []Candidate{c}); err != nil {
				t.Fatal(err)
			}
			if err := k.Remove(context.Background(), []string{c.Key}); err != nil {
				t.Fatal(err)
			}
			for _, call := range runner.calls {
				if !strings.HasPrefix(call, "wg set wg0 peer "+c.Key+" ") || strings.Contains(call, "secret-private-key") {
					t.Fatal("broad/secret mutation", call)
				}
			}
		})
	}
}

func TestMalformedDumpErrorsNeverContainRawFields(t *testing.T) {
	for _, bad := range []string{"", "private-secret", "private-secret header broken extra fields", fmt.Sprintf("private-secret %s 51820 off\n%s psk-secret host allowed handshake-secret 1 2 off", key(1), key(3)), fmt.Sprintf("private-secret %s 51820 off\n%s psk-secret host allowed -1 1 2 off", key(1), key(3))} {
		k := kernel{"wg0", "10.7.0.2", &fixtureRunner{dump: bad}}
		if _, err := k.Snapshot(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("malformed dump accepted or leaked", err)
		}
	}
}

func TestEmptyForeignAllowedIPsIsAnEmptySet(t *testing.T) {
	k := kernel{"wg0", "10.7.0.2", &fixtureRunner{dump: fmt.Sprintf("private %s 51820 off\n%s (none) (none) (none) 0 0 0 off", key(1), key(4))}}
	s, err := k.Snapshot(context.Background())
	if err != nil || len(s.Peers[key(4)].Prefixes) != 0 {
		t.Fatal(s, err)
	}
}

func TestKernelStageRetainsEmptyAllowedIPsArgument(t *testing.T) {
	runner := &fixtureRunner{}
	k := kernel{"wg0", "10.7.0.2", runner}
	c := Candidate{Key: key(3), Endpoint: "192.0.2.3:51820", Address: "10.7.0.3", Keepalive: 25}
	if err := k.Stage(context.Background(), []Candidate{c}); err != nil {
		t.Fatal(err)
	}
	want := []string{"wg", "set", "wg0", "peer", c.Key, "endpoint", c.Endpoint, "allowed-ips", "", "persistent-keepalive", "1"}
	if len(runner.argv) != 1 || !reflect.DeepEqual(runner.argv[0], want) {
		t.Fatal("staging must clear prefixes without replacing the interface", runner.argv)
	}
}
