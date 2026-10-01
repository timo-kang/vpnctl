// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"testing"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
	"vpnctl/internal/relaycache"
)

func TestRelayDeploymentCacheMTLSLifecycle(t *testing.T) {
	for _, operation := range []string{"withdraw", "pki.revoke", "node.remove"} {
		t.Run(operation, func(t *testing.T) {
			s, h, clients, dirs, c := relayFixture(t)
			ctx := context.Background()
			for _, p := range c.Spec.Paths {
				v, e := clients[p.NodeID].BindRelayPath(ctx, relayRequest(c, p.NodeID, p.ID))
				if e != nil {
					t.Fatal(e)
				}
				c.Generation = v.Generation
			}
			grantRecipient(t, s, "ra", "a")
			dir := relayCacheDirectory(t)
			opts := relaycache.DeploymentOptions{PrincipalID: "a", RelayID: "ra", Create: true}
			cache, e := relaycache.OpenDeployment(dir, opts)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { cache.Close() }()
			r, e := cache.Refresh(ctx, clients["a"])
			if e != nil || !r.ApprovalValid || len(r.Deployment.Bindings) != 2 {
				t.Fatal("initial deployment", e)
			}
			generation := r.ObservedGeneration
			for _, op := range []string{"ca.prepare", "ca.activate", "ca.rollback"} {
				if _, e = api.Admin(ctx, s.cfg.DataDir, api.AdminRequest{Operation: op}); e != nil {
					t.Fatal(e)
				}
				for id, client := range clients {
					if e = client.SyncCredentials(ctx, dirs[id], id); e != nil {
						t.Fatal(e)
					}
				}
				cache.Close()
				cache, e = relaycache.OpenDeployment(dir, opts)
				if e != nil {
					t.Fatal(e)
				}
				r, e = cache.Refresh(ctx, clients["a"])
				if e != nil || !r.ApprovalValid || r.ObservedGeneration != generation {
					t.Fatal("CA transition changed cached grant", e)
				}
			}
			if operation == "withdraw" {
				grantRecipient(t, s, "ra", "")
			} else {
				req := api.AdminRequest{Operation: operation, NodeID: "a"}
				if operation == "pki.revoke" {
					credentials, e := pki.LoadCredentials(dirs["a"])
					if e != nil {
						t.Fatal(e)
					}
					cert, e := pki.ParseCertificate(credentials.ClientCert)
					if e != nil {
						t.Fatal(e)
					}
					req.Fingerprint = pki.Fingerprint(cert)
				}
				if _, e = api.Admin(ctx, s.cfg.DataDir, req); e != nil {
					t.Fatal(e)
				}
			}
			r, e = cache.Refresh(ctx, clients["a"])
			if e == nil || r.ApprovalValid || r.Refresh.Result != "denied" {
				t.Fatal("cached grant survived denial", e)
			}
			cache.Close()
			cache, e = relaycache.OpenDeployment(dir, opts)
			if e != nil {
				t.Fatal(e)
			}
			h.Close()
			clients["a"].CloseIdleConnections()
			r, e = cache.Refresh(ctx, clients["a"])
			if e == nil || r.ApprovalValid || r.Refresh.Result != "unavailable" || r.BlockedReason == "" {
				t.Fatal("outage erased denial", e)
			}
		})
	}
}
