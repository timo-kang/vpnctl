// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/api"
	"vpnctl/internal/pki"
	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/store"
)

type lostRelayBindingReply struct {
	*api.Client
	lost bool
}

func (c *lostRelayBindingReply) BindRelayPath(ctx context.Context, req relaycatalog.BindRequest) (relaycatalog.View, error) {
	v, e := c.Client.BindRelayPath(ctx, req)
	if e == nil && !c.lost {
		c.lost = true
		return relaycatalog.View{}, io.ErrUnexpectedEOF
	}
	return v, e
}
func relayCacheDirectory(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "vpnctl-relay-cache-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func TestRelayCacheMTLSLostReplyAndDenial(t *testing.T) {
	for _, operation := range []string{"pki.revoke", "node.remove"} {
		t.Run(operation, func(t *testing.T) {
			s, h, clients, dirs, _ := relayFixture(t)
			dir := relayCacheDirectory(t)
			cache, e := relaycache.Open(dir, relaycache.Options{NodeID: "a", Create: true})
			if e != nil {
				t.Fatal(e)
			}
			defer func() { cache.Close() }()
			r, e := cache.Refresh(context.Background(), &lostRelayBindingReply{Client: clients["a"]})
			if e == nil || r.UsableCache || r.Preparation != "partial" {
				t.Fatal("lost response marked prepared", e)
			}
			pending := r.Paths[0].PublicKey
			cache.Close()
			cache, e = relaycache.Open(dir, relaycache.Options{NodeID: "a"})
			if e != nil {
				t.Fatal(e)
			}
			r, e = cache.Refresh(context.Background(), clients["a"])
			if e != nil || !r.UsableCache || r.Paths[0].PublicKey != pending || len(r.Catalog.Bindings) != 2 {
				t.Fatal("restart recovery", e)
			}
			before := r.Catalog.Generation
			r, e = cache.Refresh(context.Background(), clients["a"])
			if e != nil || r.Catalog.Generation != before {
				t.Fatal("replay changed allocation", e)
			}
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
			if _, e = api.Admin(context.Background(), s.cfg.DataDir, req); e != nil {
				t.Fatal(e)
			}
			r, e = cache.Refresh(context.Background(), clients["a"])
			if e == nil || r.UsableCache || r.Refresh.Result != "denied" {
				t.Fatal("denied identity kept usable cache", e)
			}
			h.Close()
			clients["a"].CloseIdleConnections()
			r, e = cache.Refresh(context.Background(), clients["a"])
			if e == nil || r.UsableCache || r.Refresh.Result != "unavailable" || r.BlockedReason == "" {
				t.Fatal("outage cleared identity denial", e)
			}
		})
	}
}

// Initial binding, response replay, node reopen and controller backup/reload all
// use actual mTLS and durable files. Each node races against the global CAS.
func TestRelayCacheVariableScale(t *testing.T) {
	if os.Getenv("VPNCTL_RELAY_CACHE_SCALE") != "1" {
		t.Skip("set VPNCTL_RELAY_CACHE_SCALE=1")
	}
	for _, count := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, h := lifecycleServer(t, "1h", "24h", "40m")
			base := relayCacheDirectory(t)
			clients := map[string]*api.Client{}
			dirs := map[string]string{}
			spec := relayTestSpec()
			spec.Paths = nil
			spec.PoolCIDR = "10.78.0.0/22"
			for _, id := range []string{"rc", "rd"} {
				spec.Relays = append(spec.Relays, relaycatalog.Relay{ID: id, PublicKey: relayTestKey(id), KeyGeneration: 1, Endpoints: []relaycatalog.Endpoint{{ID: "e", Address: fmt.Sprintf("203.0.113.%d:51820", len(spec.Relays)+1)}}})
			}
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("robot-%02d", i)
				clients[id], dirs[id] = lifecycleNode(t, s, h, id)
				if _, e := clients[id].Register(context.Background(), api.RegisterRequest{Name: id, PubKey: relayTestKey("legacy-" + id)}); e != nil {
					t.Fatal(e)
				}
				for _, r := range spec.Relays {
					for _, u := range []string{"wifi", "lan"} {
						spec.Paths = append(spec.Paths, relaycatalog.Path{ID: id + "-" + r.ID + "-" + u, NodeID: id, RelayID: r.ID, EndpointID: "e", UnderlayID: u, TargetIDs: []string{"app"}})
					}
				}
			}
			if _, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &relaycatalog.Update{Spec: spec, TTLSeconds: 3600}}); e != nil {
				t.Fatal(e)
			}
			type result struct {
				id     string
				report relaycache.Report
				err    error
			}
			round := func(create bool) map[string]relaycache.Report {
				t.Helper()
				results := make(chan result, count)
				start := make(chan struct{})
				var wg sync.WaitGroup
				for id, client := range clients {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						cache, e := relaycache.Open(filepath.Join(base, id), relaycache.Options{NodeID: id, Create: create, LegacyPublicKeys: []string{relayTestKey("legacy-" + id)}})
						if e != nil {
							results <- result{id: id, err: e}
							return
						}
						defer cache.Close()
						r, e := cache.Refresh(context.Background(), client)
						if e == nil && (!r.UsableCache || r.Preparation != "complete" || len(r.Catalog.Bindings) != 8 || r.RetainedKeys != 8) {
							e = fmt.Errorf("incomplete preparation: %s/%s", r.Validity, r.Preparation)
						}
						results <- result{id: id, report: r, err: e}
					}()
				}
				close(start)
				wg.Wait()
				close(results)
				reports := map[string]relaycache.Report{}
				for r := range results {
					if r.err != nil {
						t.Fatalf("%s refresh: %v", r.id, r.err)
					}
					reports[r.id] = r.report
				}
				return reports
			}
			started := time.Now()
			first := round(true)
			disk, e := store.LoadRegistry(s.regPath)
			if e != nil {
				t.Fatal(e)
			}
			if disk.RelayCatalog.Generation != uint64(count*8+1) || len(disk.RelayCatalog.Bindings) != count*8 {
				t.Fatal("duplicate/missing allocations")
			}
			leases, keys := map[string]bool{}, map[string]bool{}
			for _, b := range disk.RelayCatalog.Bindings {
				if leases[b.InnerAddress] || keys[b.PublicKey] {
					t.Fatal("duplicate key/address")
				}
				leases[b.InnerAddress] = true
				keys[b.PublicKey] = true
			}
			snapshot, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "pki.backup"})
			if e != nil {
				t.Fatal(e)
			}
			restored, e := RestoreBackup(snapshot.Backup, filepath.Join(base, "restored"))
			if e != nil {
				t.Fatal(e)
			}
			restarted, e := NewServer(*restored.Controller)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = restarted.InitPKI(); e != nil {
				t.Fatal(e)
			}
			h.Close()
			newHTTP, _, _ := testTLSAPI(t, restarted)
			for id, old := range clients {
				old.CloseIdleConnections()
				clients[id] = api.NewCredentialClient(newHTTP.URL, dirs[id])
				t.Cleanup(clients[id].CloseIdleConnections)
			}
			for pass := 0; pass < 2; pass++ {
				current := round(false)
				for id, r := range current {
					old, _ := json.Marshal(first[id].Catalog.Bindings)
					now, _ := json.Marshal(r.Catalog.Bindings)
					if string(old) != string(now) || r.Catalog.Generation != disk.RelayCatalog.Generation {
						t.Fatal("reopen/controller reload/replay changed binding", id)
					}
				}
			}
			after, e := store.LoadRegistry(restarted.regPath)
			if e != nil {
				t.Fatal(e)
			}
			if after.RelayCatalog.Generation != disk.RelayCatalog.Generation || len(after.RelayCatalog.Bindings) != count*8 {
				t.Fatal("restart/replay allocated again")
			}
			t.Logf("nodes=%d relays=4 paths=%d: concurrent preparation + two cache reopens + controller restore, stable key/IP population, elapsed=%s", count, count*8, time.Since(started).Round(time.Millisecond))
		})
	}
}
