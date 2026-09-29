// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
	"vpnctl/internal/api"
	"vpnctl/internal/relaycatalog"
	"vpnctl/internal/store"
)

// Uses real mTLS, Unix administration, atomic registry writes and PKI sync.
// Separate CI execution keeps this capacity experiment out of short race tests.
func TestRelayCatalogVariableScale(t *testing.T) {
	if os.Getenv("VPNCTL_RELAY_CATALOG_SCALE") != "1" {
		t.Skip("set VPNCTL_RELAY_CATALOG_SCALE=1")
	}
	for _, count := range []int{1, 3, 8, 32} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, h := lifecycleServer(t, "1h", "24h", "40m")
			clients := map[string]*api.Client{}
			dirs := map[string]string{}
			spec := relayTestSpec()
			spec.PoolCIDR = "10.78.0.0/22"
			spec.Paths = nil
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
			result, e := api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.apply", RelayCatalog: &relaycatalog.Update{Spec: spec, TTLSeconds: 3600}})
			if e != nil {
				t.Fatal(e)
			}
			c := result.RelayCatalog
			// Continuous legacy registration and committed catalog reads while the
			// increasingly large catalog is persisted by the binding writer.
			stop := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				for {
					select {
					case <-stop:
						done <- nil
						return
					default:
					}
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_, e := clients["robot-00"].Register(ctx, api.RegisterRequest{Name: "robot-00", PubKey: relayTestKey("legacy-robot-00")})
					if e == nil {
						_, e = clients["robot-00"].RelayCatalog(ctx, "robot-00")
					}
					cancel()
					if e != nil {
						done <- e
						return
					}
					select {
					case <-stop:
						done <- nil
						return
					case <-time.After(50 * time.Millisecond):
					}
				}
			}()
			var stopOnce sync.Once
			joined := false
			defer func() {
				stopOnce.Do(func() { close(stop) })
				if !joined {
					<-done
				}
			}()
			for _, p := range spec.Paths {
				v, e := clients[p.NodeID].BindRelayPath(context.Background(), relayRequest(c, p.NodeID, p.ID))
				if e != nil {
					t.Fatal(e)
				}
				// Legacy writes do not advance catalog generation.
				c.Generation = v.Generation
			}
			stopOnce.Do(func() { close(stop) })
			e = <-done
			joined = true
			if e != nil {
				t.Fatal("2s concurrent control/read budget", e)
			}
			result, e = api.Admin(context.Background(), s.cfg.DataDir, api.AdminRequest{Operation: "relay.catalog.status"})
			if e != nil {
				t.Fatal(e)
			}
			c = result.RelayCatalog
			if len(c.Bindings) != count*8 || c.Generation != uint64(count*8+1) {
				t.Fatal("allocation population", len(c.Bindings), c.Generation)
			}
			before := c.Generation
			errs := make(chan error, count)
			var wg sync.WaitGroup
			for id, client := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					v, e := client.RelayCatalog(ctx, id)
					if e != nil {
						errs <- e
						return
					}
					if len(v.Bindings) != 8 || len(v.Spec.Paths) != 8 {
						errs <- fmt.Errorf("node %s has foreign or missing paths", id)
						return
					}
					for i := 0; i < 4; i++ {
						if _, e = client.BindRelayPath(ctx, relayRequest(c, id, id+"-ra-wifi")); e != nil {
							errs <- e
							return
						}
					}
					errs <- client.SyncCredentials(ctx, dirs[id], id)
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				if e != nil {
					t.Fatal(e)
				}
			}
			disk, e := store.LoadRegistry(s.regPath)
			if e != nil {
				t.Fatal(e)
			}
			if disk.RelayCatalog.Generation != before || len(disk.RelayCatalog.Bindings) != count*8 {
				t.Fatal("replay/PKI changed allocation population")
			}
			if e = validateRelayRegistry(disk, s.cfg); e != nil {
				t.Fatal(e)
			}
			t.Logf("nodes=%d relays=4 candidates=%d unique durable bindings=%d; concurrent legacy registration/catalog read <=2s; 4 replays/node + PKI sync", count, count*8, len(c.Bindings))
		})
	}
}
