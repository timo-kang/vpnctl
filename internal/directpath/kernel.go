// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package directpath

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"vpnctl/internal/direct"
	"vpnctl/internal/execx"
)

type identity struct {
	Index     int    `json:"index"`
	Alias     string `json:"alias"`
	PublicKey string `json:"public_key"`
}
type kernelPeer struct {
	Key, Endpoint string
	Prefixes      []string
	Keepalive     int
	PSK           bool
	Handshake     int64
	RX, TX        uint64
}
type snapshot struct {
	Identity identity
	Peers    map[string]kernelPeer
}
type backend interface {
	Snapshot(context.Context) (snapshot, error)
	Stage(context.Context, []Candidate) error
	Add(context.Context, []Candidate) error
	Remove(context.Context, []string) error
	Probe(context.Context, Candidate) error
}
type kernel struct {
	iface, source string
	run           execx.ContextRunner
}

func newKernel(iface, source string) kernel {
	return kernel{iface, source, execx.NewOSRunner(io.Discard, io.Discard)}
}
func (k kernel) Snapshot(ctx context.Context) (snapshot, error) {
	s := snapshot{Peers: map[string]kernelPeer{}}
	b, err := k.run.OutputContext(ctx, "ip", "-j", "-d", "link", "show", "dev", k.iface)
	if err != nil {
		return s, errors.New("direct interface unavailable")
	}
	var links []struct {
		Index int    `json:"ifindex"`
		Alias string `json:"ifalias"`
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal([]byte(b), &links) != nil || len(links) != 1 || links[0].Index <= 0 || links[0].Info.Kind != "wireguard" {
		return s, errors.New("not a WireGuard interface")
	}
	s.Identity.Index, s.Identity.Alias = links[0].Index, links[0].Alias
	// Raw dump contains private material. Never include it in errors/reports or journal.
	raw, err := k.run.OutputContext(ctx, "wg", "show", k.iface, "dump")
	if err != nil {
		return s, errors.New("WireGuard readback unavailable")
	}
	if len(raw) > 512<<10 {
		return s, errors.New("WireGuard readback too large")
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	fields := strings.Fields(lines[0])
	if len(fields) != 4 {
		return s, errors.New("invalid WireGuard header")
	}
	s.Identity.PublicKey = fields[1]
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != 8 {
			return s, errors.New("invalid WireGuard peer")
		}
		if _, ok := s.Peers[f[0]]; ok {
			return s, errors.New("duplicate WireGuard peer")
		}
		p := kernelPeer{Key: f[0], Endpoint: f[2], Prefixes: strings.Split(f[3], ","), PSK: f[1] != "(none)"}
		if f[3] == "(none)" {
			p.Prefixes = nil
		}
		var e error
		if p.Handshake, e = strconv.ParseInt(f[4], 10, 64); e != nil || p.Handshake < 0 {
			return s, errors.New("invalid WireGuard handshake")
		}
		if p.RX, e = strconv.ParseUint(f[5], 10, 64); e != nil {
			return s, errors.New("invalid WireGuard receive count")
		}
		if p.TX, e = strconv.ParseUint(f[6], 10, 64); e != nil {
			return s, errors.New("invalid WireGuard transmit count")
		}
		if f[7] != "off" {
			if p.Keepalive, e = strconv.Atoi(f[7]); e != nil || p.Keepalive < 0 || p.Keepalive > 65535 {
				return s, errors.New("invalid WireGuard keepalive")
			}
		}
		s.Peers[p.Key] = p
	}
	return s, nil
}

// No AllowedIPs means neither outgoing application selection nor incoming IP
// authorization moves from the relay. Keepalives establish only WG transport.
func (k kernel) Stage(ctx context.Context, candidates []Candidate) error {
	args := []string{"set", k.iface}
	for _, c := range candidates {
		args = append(args, "peer", c.Key, "endpoint", c.Endpoint, "allowed-ips", "", "persistent-keepalive", "1")
	}
	return k.run.RunContext(ctx, "wg", args...)
}

func (k kernel) Add(ctx context.Context, candidates []Candidate) error {
	args := []string{"set", k.iface}
	for _, c := range candidates {
		args = append(args, "peer", c.Key, "endpoint", c.Endpoint, "allowed-ips", c.Address+"/32", "persistent-keepalive", strconv.Itoa(c.Keepalive))
	}
	return k.run.RunContext(ctx, "wg", args...)
}
func (k kernel) Remove(ctx context.Context, keys []string) error {
	args := []string{"set", k.iface}
	for _, key := range keys {
		args = append(args, "peer", key, "remove")
	}
	return k.run.RunContext(ctx, "wg", args...)
}
func (k kernel) Probe(ctx context.Context, c Candidate) error {
	_, err := direct.ProbeInterface(ctx, k.iface, k.source, c.Address+":"+strconv.Itoa(c.ProbePort), time.Second)
	return err
}
