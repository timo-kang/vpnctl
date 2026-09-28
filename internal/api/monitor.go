// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"vpnctl/internal/history"
	"vpnctl/internal/observation"
	"vpnctl/internal/wgstats"
)

const MaxMonitorPeers = 1024

// MonitorPeer identifies the registered peer at observation time. Epoch changes
// with its key/address binding; it is not a claim about the packet's route.
type MonitorPeer = wgstats.Binding
type MonitorPeersResponse struct {
	Self          MonitorPeer   `json:"self"`
	SchemaVersion int           `json:"schema_version"`
	Peers         []MonitorPeer `json:"peers"`
}
type MonitorMetricsRequest struct {
	NodeID      string              `json:"node_id"`
	Peer        MonitorPeer         `json:"peer"`
	Observation history.Observation `json:"observation"`
}

func (c *Client) MonitorPeers(ctx context.Context, node string) (MonitorPeersResponse, error) {
	var out MonitorPeersResponse
	err := c.getJSON(ctx, "/monitor/peers?node_id="+url.QueryEscape(node), &out)
	if err == nil && (out.SchemaVersion != 1 || len(out.Peers) > MaxMonitorPeers) {
		err = fmt.Errorf("unsupported or excessive monitor peer catalog")
	}
	return out, err
}
func (c *Client) SubmitMonitorMetrics(ctx context.Context, req MonitorMetricsRequest) error {
	return c.postJSON(ctx, "/monitor/metrics", req, nil)
}

// HistoryDeliveryResult shares the same bounded queue retry classification
// between direct and overlay producers. A quota is not a transport outage.
func HistoryDeliveryResult(err error) (bool, error) {
	var response *HTTPError
	if errors.As(err, &response) {
		if response.StatusCode == http.StatusServiceUnavailable && response.Code == CodeHistoryQuota {
			return false, errors.Join(observation.ErrQuotaRejected, err)
		}
		code := response.StatusCode
		return code != 400 && code != 409 && code != 413 && code != 404, err
	}
	return true, err
}

func (c *Client) SubmitWireGuard(ctx context.Context, r wgstats.Report) error {
	return c.postJSON(ctx, "/monitor/wireguard", r, nil)
}

func (c *Client) FleetWireGuard(ctx context.Context, node, window string, limit int) (history.WireGuardHistory, error) {
	var out history.WireGuardHistory
	q := url.Values{"node_id": {node}, "window": {window}, "limit": {strconv.Itoa(limit)}}
	err := c.getJSON(ctx, "/fleet/wireguard?"+q.Encode(), &out)
	if err == nil && out.SchemaVersion != 1 {
		err = fmt.Errorf("unsupported WireGuard history schema")
	}
	return out, err
}
