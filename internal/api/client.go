// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"vpnctl/internal/diagnostic"
	"vpnctl/internal/history"
)

const CodeHistoryQuota = "history_quota"
const CodeHistorySealed = "history_sealed"

// ErrorResponse adds an optional machine-readable classification to the legacy
// error message. Callers retain status-based handling for unknown/missing codes.
type ErrorResponse struct {
	Error    string `json:"error"`
	Code     string `json:"code,omitempty"`
	Resource string `json:"resource,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// HTTPError preserves the response status and code for producer retry decisions.
type HTTPError struct {
	StatusCode      int
	Status, Message string
	Code            string
}

func responseError(res *http.Response) *HTTPError {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8192))
	e := &HTTPError{StatusCode: res.StatusCode, Status: res.Status, Message: strings.TrimSpace(string(body))}
	var response ErrorResponse
	if json.Unmarshal(body, &response) == nil {
		e.Code = response.Code
	}
	return e
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("request failed: %s: %s", e.Status, e.Message)
	}
	return "request failed: " + e.Status
}

// Client is a thin HTTP client for the controller API.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient creates a client for the given base URL (e.g. http://host:port).
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewTLSClient creates a client with custom TLS configuration.
func NewTLSClient(baseURL string, tlsConfig *tls.Config) *Client {
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}
}

// Register registers a node and returns peer candidates.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (resp RegisterResponse, resultErr error) {
	defer func() { diagnostic.Discovery(ctx, "registration", resultErr) }()
	if err := c.postJSON(ctx, "/register", req, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// Bootstrap enrolls a node using a bootstrap token and CSR.
func (c *Client) Bootstrap(ctx context.Context, req BootstrapRequest) (BootstrapResponse, error) {
	var resp BootstrapResponse
	if err := c.postJSON(ctx, "/bootstrap", req, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// Candidates fetches peer candidates for a node ID.
func (c *Client) Candidates(ctx context.Context, nodeID string) (resp CandidatesResponse, resultErr error) {
	defer func() { diagnostic.Discovery(ctx, "candidates", resultErr) }()
	endpoint := "/candidates?node_id=" + url.QueryEscape(nodeID)
	if err := c.getJSON(ctx, endpoint, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// SubmitMetrics sends metrics samples to the controller.
func (c *Client) SubmitMetrics(ctx context.Context, req MetricsRequest) error {
	return c.postJSON(ctx, "/metrics", req, nil)
}

// SubmitNATProbe sends NAT probe results to the controller.
func (c *Client) SubmitNATProbe(ctx context.Context, req NATProbeRequest) (resultErr error) {
	defer func() { diagnostic.Discovery(ctx, "nat-report", resultErr) }()
	return c.postJSON(ctx, "/nat-probe", req, nil)
}

// SubmitDirectResult sends a direct path attempt result.
func (c *Client) SubmitDirectResult(ctx context.Context, req DirectResultRequest) error {
	return c.postJSON(ctx, "/direct-result", req, nil)
}

// WGConfig fetches controller-provided server peer settings.
func (c *Client) WGConfig(ctx context.Context, nodeID string) (resp WGConfigResponse, resultErr error) {
	defer func() { diagnostic.Discovery(ctx, "server-config", resultErr) }()
	endpoint := "/wg-config?node_id=" + url.QueryEscape(nodeID)
	if err := c.getJSON(ctx, endpoint, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// FleetStatus fetches the current status of all fleet nodes.
func (c *Client) FleetStatus(ctx context.Context) (FleetStatusResponse, error) {
	var resp FleetStatusResponse
	if err := c.getJSON(ctx, "/fleet/status", &resp); err != nil {
		return resp, err
	}
	if resp.SchemaVersion != 2 {
		return resp, fmt.Errorf("unsupported fleet schema %d; controller and client must support v2", resp.SchemaVersion)
	}
	return resp, nil
}

// FleetHistory fetches the first history page. In v3, Tiering.NextCursor signals
// additional streams; FleetHistoryPage continues with the same filters.
func (c *Client) FleetHistory(ctx context.Context, window string) (FleetHistoryResponse, error) {
	return c.FleetHistoryQuery(ctx, window, "", "")
}

func (c *Client) FleetHistoryQuery(ctx context.Context, window, nodeID, bucket string) (FleetHistoryResponse, error) {
	return c.FleetHistoryPage(ctx, window, nodeID, bucket, "", "")
}

// FleetHistoryPage returns one bounded page. Callers must follow NextCursor
// explicitly; collecting every stream is not silently folded into one response.
func (c *Client) FleetHistoryPage(ctx context.Context, window, nodeID, bucket, source, cursor string) (FleetHistoryResponse, error) {
	var resp FleetHistoryResponse
	values := url.Values{"window": {window}, "node_id": {nodeID}, "bucket": {bucket}, "source": {source}, "cursor": {cursor}}
	if err := c.getJSON(ctx, "/fleet/history?"+values.Encode(), &resp); err != nil {
		return resp, err
	}
	if resp.SchemaVersion != 2 && resp.SchemaVersion != 3 {
		return resp, fmt.Errorf("unsupported fleet history schema %d; supported: v2, v3", resp.SchemaVersion)
	}
	if resp.SchemaVersion == 3 && (resp.Tiering == nil || resp.Storage == nil) {
		return resp, fmt.Errorf("incomplete fleet history v3: tiering and storage metadata required")
	}
	return resp, nil
}

func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return responseError(res)
	}

	if out == nil {
		return nil
	}

	decoder := json.NewDecoder(res.Body)
	return decoder.Decode(out)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return responseError(res)
	}

	decoder := json.NewDecoder(res.Body)
	return decoder.Decode(out)
}

func (c *Client) SubmitUplink(ctx context.Context, req UplinkRequest) error {
	return c.postJSON(ctx, "/uplink-observations", req, nil)
}
func (c *Client) FleetUplinks(ctx context.Context, node, window string, limit int) (history.UplinkHistory, error) {
	var out history.UplinkHistory
	values := url.Values{"node_id": {node}, "window": {window}, "limit": {fmt.Sprint(limit)}}
	err := c.getJSON(ctx, "/fleet/uplinks?"+values.Encode(), &out)
	if err == nil && out.SchemaVersion != 1 {
		err = fmt.Errorf("unsupported uplink history schema %d", out.SchemaVersion)
	}
	return out, err
}

func (c *Client) SubmitEvent(ctx context.Context, req EventRequest) error {
	return c.postJSON(ctx, "/events", req, nil)
}

func (c *Client) FleetEvents(ctx context.Context, node, window string, limit int) (history.EventHistory, error) {
	var out history.EventHistory
	values := url.Values{"node_id": {node}, "window": {window}, "limit": {fmt.Sprint(limit)}}
	if node == "" {
		values.Del("node_id")
		values.Set("scope", "controller")
	}
	err := c.getJSON(ctx, "/fleet/events?"+values.Encode(), &out)
	if err == nil && out.SchemaVersion != 1 {
		err = fmt.Errorf("unsupported event history schema %d", out.SchemaVersion)
	}
	return out, err
}

func (c *Client) FleetAlerts(ctx context.Context, node string) ([]history.Alert, error) {
	var out []history.Alert
	values := url.Values{"node_id": {node}}
	err := c.getJSON(ctx, "/fleet/alerts?"+values.Encode(), &out)
	return out, err
}
