// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"vpnctl/internal/agent"
	"vpnctl/internal/api"
	"vpnctl/internal/config"
	"vpnctl/internal/direct"
	"vpnctl/internal/history"
	"vpnctl/internal/pki"
)

func TestAutomaticProbeHistoryOverMTLSAndRemoval(t *testing.T) {
	s, h := lifecycleServer(t, "90s")
	robot, dir := lifecycleNode(t, s, h, "robot")
	remote, err := direct.StartResponder("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	address, _ := net.ResolveUDPAddr("udp", remote.LocalAddr())
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	for _, peer := range []struct {
		name, address string
		port          int
	}{{"success", remote.LocalAddr(), address.Port}, {"failure", silent.LocalAddr().String(), silent.LocalAddr().(*net.UDPAddr).Port}, {"unknown", "", 0}} {
		client, _ := lifecycleNode(t, s, h, peer.name)
		if _, err := client.Register(context.Background(), api.RegisterRequest{Name: peer.name, PubKey: "pub-" + peer.name, PublicAddr: peer.address, ProbePort: peer.port, DirectMode: "off"}); err != nil {
			t.Fatal(err)
		}
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Run(ctx, config.NodeConfig{Name: "robot", Controller: h.URL, PKIDir: dir, WGPublicKey: "pub-robot", ProbePort: port, DirectMode: "auto", DirectIntervalSec: 1, CandidatesIntervalSec: 1, KeepaliveIntervalSec: 1})
	}()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			<-done
		}
	}()
	waitPKI(t, 8*time.Second, func() bool {
		resp, err := robot.FleetHistoryQuery(context.Background(), "1h", "robot", "1h")
		if err != nil {
			return false
		}
		if len(resp.Nodes) != 1 {
			return false
		}
		states := map[string]bool{}
		for _, b := range resp.Nodes[0].Buckets {
			if b.Source != "agent-direct" {
				t.Error("producer source missing", b)
				return false
			}
			switch b.PeerID {
			case "success":
				states[b.PeerID] = b.Count > 0 && b.Successes == b.Count && b.AvgRTTMs != nil
			case "failure":
				states[b.PeerID] = b.Count > 0 && b.Successes == 0 && b.AvgRTTMs == nil && b.LossPct != nil && *b.LossPct == 100
			case "unknown":
				states[b.PeerID] = b.Count == 0 && b.UnknownCount > 0 && b.AvgRTTMs == nil && b.LossPct == nil
			}
		}
		return states["success"] && states["failure"] && states["unknown"]
	})
	cancel()
	<-done
	stopped = true
	status, err := robot.FleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range status.Nodes {
		if n.NodeID == "robot" {
			for _, m := range n.Measurements {
				if m.Quality != "unknown" {
					t.Fatal("public UDP declared VPN healthy", m)
				}
			}
		}
	}
	rejected := history.Observation{ID: "removed-peer", Timestamp: time.Now(), PeerID: "success", Path: "direct", Source: "agent-direct", Validity: "unknown", Reason: "collector_unavailable"}
	if _, err := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "node.remove", NodeID: "success"}); err != nil {
		t.Fatal(err)
	}
	err = robot.SubmitMetrics(context.Background(), api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{rejected}})
	var response *api.HTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusBadRequest {
		t.Fatal("removed peer accepted", err)
	}
	creds, err := pki.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(creds.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.authority.Revoke(certificateFingerprint(cert)); err != nil {
		t.Fatal(err)
	}
	rejected.PeerID = "failure"
	rejected.ID = "revoked-reporter"
	err = robot.SubmitMetrics(context.Background(), api.MetricsRequest{NodeID: "robot", Observations: []history.Observation{rejected}})
	if !errors.As(err, &response) || response.StatusCode != http.StatusForbidden {
		t.Fatal("revoked producer accepted", err)
	}
}
