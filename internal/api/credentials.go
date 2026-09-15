// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
)

// credentialTransport reloads only complete credential generations. A configured
// PKI path always requires HTTPS; missing/corrupt credentials never downgrade it.
type credentialTransport struct {
	mu          sync.Mutex
	dir, digest string
	current     *http.Transport
}

func (t *credentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("PKI client requires HTTPS")
	}
	t.mu.Lock()
	creds, err := pki.LoadCredentials(t.dir)
	if err != nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("load PKI credentials: %w", err)
	}
	digest := creds.Digest()
	if t.current == nil || t.digest != digest {
		cfg, err := creds.TLSConfig()
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		if t.current != nil {
			t.current.CloseIdleConnections()
		}
		t.current = &http.Transport{TLSClientConfig: cfg}
		t.digest = digest
	}
	transport := t.current
	t.mu.Unlock()
	return transport.RoundTrip(req)
}
func (t *credentialTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current != nil {
		t.current.CloseIdleConnections()
	}
}

func NewCredentialClient(baseURL, dir string) *Client {
	if strings.HasPrefix(baseURL, "http://") {
		baseURL = "https://" + strings.TrimPrefix(baseURL, "http://")
	}
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second, Transport: &credentialTransport{dir: dir}}}
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

// SyncCredentials persists trust before acknowledging it, renews before expiry
// or after an issuer change, then acknowledges using the installed certificate.
func (c *Client) SyncCredentials(ctx context.Context, dir, nodeID string) error {
	current, err := pki.LoadCredentials(dir)
	if err != nil {
		return err
	}
	trust, err := c.Trust(ctx)
	if err != nil {
		return err
	}
	if trust.Generation < current.Generation {
		return fmt.Errorf("controller trust generation moved backwards; recovery requires explicit re-enrollment")
	}
	next := current
	next.Generation, next.CACert = trust.Generation, trust.CACert
	cert, err := pki.ParseCertificate(current.ClientCert)
	if err != nil {
		return err
	}
	issuerIsActive := false
	canExtend := true
	cfg, err := next.TLSConfig()
	if err != nil {
		return err
	}
	// Authority records use the root fingerprint; get it from the verified chain.
	chains, err := cert.Verify(clientVerifyOptions(cfg.RootCAs))
	if err == nil {
		for _, chain := range chains {
			if pki.Fingerprint(chain[len(chain)-1]) == trust.Active {
				issuerIsActive = true
				canExtend = cert.NotAfter.Before(chain[len(chain)-1].NotAfter)
			}
		}
	}
	needsRenewal := !issuerIsActive || (canExtend && time.Until(cert.NotAfter) <= time.Duration(trust.RenewBeforeSeconds*float64(time.Second)))
	if next.Digest() != current.Digest() {
		if err := next.ValidateForInstall(nodeID); err != nil {
			return err
		}
		if err := pki.SaveCredentials(dir, next, current.Digest()); err != nil {
			return err
		}
		current = next
	}
	if needsRenewal {
		if current.Pending == nil || current.Pending.Parent != pki.Fingerprint(cert) {
			csr, key, err := pki.GenerateCSR(nodeID)
			if err != nil {
				return err
			}
			staged := current
			staged.Pending = &pki.PendingRenewal{Parent: pki.Fingerprint(cert), CSR: string(csr), Key: string(key)}
			if err := pki.SaveCredentials(dir, staged, current.Digest()); err != nil {
				return err
			}
			current = staged
		}
		renewed, err := c.Renew(ctx, current.Pending.CSR)
		if err != nil {
			return err
		}
		if renewed.Generation < current.Generation {
			return fmt.Errorf("stale renewal response")
		}
		next = pki.Credentials{Version: 1, Generation: renewed.Generation, CACert: renewed.CACert, ClientCert: renewed.ClientCert, ClientKey: current.Pending.Key}
		if err := next.ValidateForInstall(nodeID); err != nil {
			return err
		}
		if err := pki.SaveCredentials(dir, next, current.Digest()); err != nil {
			return err
		}
		current = next
		metrics.PKIEventsTotal.WithLabelValues("node", "renew", "success").Inc()
		slog.Info("client certificate renewed", "node_id", nodeID, "generation", current.Generation)
	}
	cert, err = pki.ParseCertificate(current.ClientCert)
	if err != nil {
		return err
	}
	metrics.PKIExpirySeconds.WithLabelValues("client").Set(time.Until(cert.NotAfter).Seconds())
	return c.AcknowledgeTrust(ctx, current.Generation)
}

// MaintainCredentials retries with a bounded exponential delay. A successful
// sync uses a fraction of the remaining lifetime (at most one minute), leaving
// repeated opportunities before expiry even with short test/field lifetimes.
func (c *Client) MaintainCredentials(ctx context.Context, dir, nodeID string) {
	delay := time.Duration(0)
	failures := 0
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		err := c.SyncCredentials(ctx, dir, nodeID)
		if err != nil {
			failures++
			metrics.PKIEventsTotal.WithLabelValues("node", "sync", "failed").Inc()
			slog.Warn("client PKI sync failed", "node_id", nodeID, "attempt", failures, "err", err)
			delay = min(time.Minute, time.Second*time.Duration(1<<min(failures-1, 6)))
		} else {
			failures = 0
			delay = time.Minute
		}
		if creds, loadErr := pki.LoadCredentials(dir); loadErr == nil {
			if cert, parseErr := pki.ParseCertificate(creds.ClientCert); parseErr == nil {
				left := time.Until(cert.NotAfter)
				metrics.PKIExpirySeconds.WithLabelValues("client").Set(left.Seconds())
				if left > 0 {
					delay = min(delay, max(100*time.Millisecond, left/6))
				}
				if err != nil && left < time.Minute {
					slog.Warn("client certificate expiry imminent", "node_id", nodeID, "remaining_seconds", left.Seconds())
				}
			}
		}
	}
}

func clientVerifyOptions(roots *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}
