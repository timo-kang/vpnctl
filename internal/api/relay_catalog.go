// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	"vpnctl/internal/relaycatalog"
)

func (c *Client) RelayCatalog(ctx context.Context, nodeID string) (relaycatalog.View, error) {
	var v relaycatalog.View
	query := url.Values{"schema_version": {"1"}, "node_id": {nodeID}}
	if e := c.relayJSON(ctx, http.MethodGet, "/relay-catalog?"+query.Encode(), nil, &v); e != nil {
		return v, e
	}
	return v, v.Validate(nodeID, time.Now())
}
func (c *Client) BindRelayPath(ctx context.Context, req relaycatalog.BindRequest) (relaycatalog.View, error) {
	var v relaycatalog.View
	if e := c.relayJSON(ctx, http.MethodPost, "/relay-bindings", req, &v); e != nil {
		return v, e
	}
	if e := v.Validate(req.NodeID, time.Now()); e != nil {
		return v, e
	}
	if v.ControllerID != req.ControllerID || v.Generation < req.ExpectedGeneration {
		return v, fmt.Errorf("relay binding response identity/generation mismatch")
	}
	for _, b := range v.Bindings {
		if b.PathID == req.PathID && b.PublicKey == req.PublicKey {
			return v, nil
		}
	}
	return v, fmt.Errorf("relay binding response missing requested key/path")
}

// This versioned contract bounds decoding before allocating descriptor slices.
func (c *Client) relayJSON(ctx context.Context, method, path string, body any, out *relaycatalog.View) error {
	var payload []byte
	var e error
	if body != nil {
		payload, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := c.http.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return responseError(res)
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, relaycatalog.MaxDocumentBytes+1))
	if e != nil {
		return e
	}
	if len(raw) > relaycatalog.MaxDocumentBytes {
		return fmt.Errorf("relay catalog response exceeds 1MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(out); e != nil {
		return e
	}
	if e = decoder.Decode(new(any)); e != io.EOF {
		return fmt.Errorf("relay catalog response must contain one JSON document")
	}
	return nil
}
