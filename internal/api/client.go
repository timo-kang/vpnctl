package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

// Register registers a node and returns peer candidates.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.postJSON(ctx, "/register", req, &resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// Candidates fetches peer candidates for a node ID.
func (c *Client) Candidates(ctx context.Context, nodeID string) (CandidatesResponse, error) {
	var resp CandidatesResponse
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
func (c *Client) SubmitNATProbe(ctx context.Context, req NATProbeRequest) error {
	return c.postJSON(ctx, "/nat-probe", req, nil)
}

// SubmitDirectResult sends a direct path attempt result.
func (c *Client) SubmitDirectResult(ctx context.Context, req DirectResultRequest) error {
	return c.postJSON(ctx, "/direct-result", req, nil)
}

// WGConfig fetches controller-provided server peer settings.
func (c *Client) WGConfig(ctx context.Context, nodeID string) (WGConfigResponse, error) {
	var resp WGConfigResponse
	endpoint := "/wg-config?node_id=" + url.QueryEscape(nodeID)
	if err := c.getJSON(ctx, endpoint, &resp); err != nil {
		return resp, err
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
		body, _ := io.ReadAll(res.Body)
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			return fmt.Errorf("request failed: %s: %s", res.Status, msg)
		}
		return fmt.Errorf("request failed: %s", res.Status)
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
		body, _ := io.ReadAll(res.Body)
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			return fmt.Errorf("request failed: %s: %s", res.Status, msg)
		}
		return fmt.Errorf("request failed: %s", res.Status)
	}

	decoder := json.NewDecoder(res.Body)
	return decoder.Decode(out)
}
