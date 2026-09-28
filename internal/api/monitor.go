// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"vpnctl/internal/history"
	"vpnctl/internal/observation"
)

const MaxMonitorPeers = 1024

// MonitorPeer identifies the registered peer at observation time. Epoch changes
// with its key/address binding; it is not a claim about the packet's route.
type MonitorPeer struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	VPNIP     string `json:"vpn_ip"`
	Epoch     string `json:"epoch"`
}
type MonitorPeersResponse struct {
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
