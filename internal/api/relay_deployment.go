// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"vpnctl/internal/relaycatalog"
)

// RelayDeployment returns an online snapshot, not a durable offline approval.
// principal is checked against the response; only the client certificate grants
// authority at the server. The relaycache deployment store additionally pins
// controller ID and rejects generation rollback or same-generation changes.
func (c *Client) RelayDeployment(ctx context.Context, principal, relayID string) (relaycatalog.DeploymentView, error) {
	var v relaycatalog.DeploymentView
	query := url.Values{"schema_version": {"1"}, "relay_id": {relayID}}
	if e := c.relayJSON(ctx, http.MethodGet, "/relay-deployment?"+query.Encode(), nil, &v); e != nil {
		return relaycatalog.DeploymentView{}, e
	}
	if e := v.Validate(principal, relayID, time.Now()); e != nil {
		return relaycatalog.DeploymentView{}, e
	}
	return v, nil
}
