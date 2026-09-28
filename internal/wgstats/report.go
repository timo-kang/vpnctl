// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package wgstats

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"time"
	"unicode"
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

const MaxReportBytes = 1 << 20
const ReportInterval = time.Minute
const Retention = 7 * 24 * time.Hour

type Binding struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	VPNIP     string `json:"vpn_ip"`
	Epoch     string `json:"epoch"`
}

func (b Binding) Validate() error {
	for _, r := range b.NodeID {
		if unicode.IsControl(r) {
			return fmt.Errorf("invalid identity")
		}
	}
	key, e := base64.StdEncoding.DecodeString(b.PublicKey)
	epoch, ee := hex.DecodeString(b.Epoch)
	_, ipErr := netip.ParseAddr(b.VPNIP)
	if b.NodeID == "" || len(b.NodeID) > 128 || e != nil || len(key) != 32 || ee != nil || (len(epoch) != 16 && len(epoch) != 32) || ipErr != nil {
		return fmt.Errorf("invalid WireGuard identity")
	}
	return nil
}

type Reading struct {
	Peer   Binding `json:"peer"`
	Sample Sample  `json:"sample"`
}
type Report struct {
	CollectionReason string    `json:"collection_reason"`
	ID               string    `json:"id"`
	ObservedAt       time.Time `json:"observed_at"`
	Reporter         Binding   `json:"reporter"`
	Interface        string    `json:"interface"`
	Peers            []Reading `json:"peers"`
	Unmapped         int       `json:"unmapped_peers"`
}

func (r Report) Validate(now time.Time) error {
	id, e := hex.DecodeString(r.ID)
	if e != nil || len(id) != 16 || r.ObservedAt.IsZero() || r.ObservedAt.After(now) || !r.ObservedAt.After(now.Add(-Retention)) || r.Reporter.Validate() != nil || len(r.Interface) < 1 || len(r.Interface) > 15 || len(r.Peers) > MaxPeers || r.Unmapped < 0 || r.Unmapped > MaxPeers {
		return fmt.Errorf("invalid WireGuard report")
	}
	if r.CollectionReason != "" {
		if Unknown(r.ObservedAt, r.CollectionReason).Validate() != nil {
			return fmt.Errorf("invalid collection reason")
		}
	}
	if !interfaceName.MatchString(r.Interface) {
		return fmt.Errorf("invalid interface name")
	}
	seen := map[string]bool{}
	keys := map[string]bool{}
	ips := map[string]bool{}
	for _, p := range r.Peers {
		if (r.CollectionReason != "" && p.Sample.Reason != r.CollectionReason) || p.Peer.Validate() != nil || p.Peer.NodeID == r.Reporter.NodeID || seen[p.Peer.NodeID] || keys[p.Peer.PublicKey] || ips[p.Peer.VPNIP] || !p.Sample.ObservedAt.Equal(r.ObservedAt) || p.Sample.Validate() != nil {
			return fmt.Errorf("invalid WireGuard reading")
		}
		seen[p.Peer.NodeID] = true
		keys[p.Peer.PublicKey] = true
		ips[p.Peer.VPNIP] = true
	}
	return nil
}
func (r Report) Clone() Report {
	r.Peers = append([]Reading{}, r.Peers...)
	for i := range r.Peers {
		r.Peers[i].Sample = r.Peers[i].Sample.Clone()
	}
	return r
}

type PeerView struct {
	Peer Binding `json:"peer"`
	View
}
type Snapshot struct {
	ViewsTruncated bool `json:"views_truncated"`
	Report
	Views []PeerView `json:"views"`
}

func CompareReport(r Report, previous *Report, now time.Time) Snapshot {
	out := Snapshot{Report: r.Clone(), Views: []PeerView{}}
	old := map[Binding]Sample{}
	if previous != nil && previous.Reporter == r.Reporter && previous.Interface == r.Interface {
		for _, p := range previous.Peers {
			old[p.Peer] = p.Sample
		}
	}
	for _, p := range r.Peers {
		var prev *Sample
		if v, ok := old[p.Peer]; ok {
			prev = &v
		}
		out.Views = append(out.Views, PeerView{Peer: p.Peer, View: Compare(p.Sample, prev).Fresh(now, MaxGap)})
	}
	return out
}
