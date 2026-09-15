// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import "context"

// TrustState contains public trust and renewal policy, never other nodes' data.
type TrustState struct {
	Generation         uint64  `json:"generation"`
	CACert             string  `json:"ca_cert"`
	Active             string  `json:"active"`
	Phase              string  `json:"phase"`
	RenewBeforeSeconds float64 `json:"renew_before_seconds"`
}

type RenewRequest struct {
	CSR string `json:"csr"`
}
type RenewResponse struct {
	TrustState
	ClientCert string `json:"client_cert"`
}
type TrustAckRequest struct {
	Generation uint64 `json:"generation"`
}

func (c *Client) Trust(ctx context.Context) (TrustState, error) {
	var out TrustState
	err := c.getJSON(ctx, "/pki/trust", &out)
	return out, err
}
func (c *Client) Renew(ctx context.Context, csr string) (RenewResponse, error) {
	var out RenewResponse
	err := c.postJSON(ctx, "/pki/renew", RenewRequest{CSR: csr}, &out)
	return out, err
}
func (c *Client) AcknowledgeTrust(ctx context.Context, generation uint64) error {
	return c.postJSON(ctx, "/pki/ack", TrustAckRequest{Generation: generation}, nil)
}
