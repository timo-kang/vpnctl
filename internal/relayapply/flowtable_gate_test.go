// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFlowtableFailureCannotReadStatusOrRenew(t *testing.T) {
	engine, _, _, _, options, _ := deploymentFixture(t, 1)
	approval, _ := engine.cache.Status()
	entry, _ := desiredDeployment(approval, options.EndpointID, options.ListenPort)
	entry.Alias, entry.Group, entry.LinkIndex, _ = token()
	entry.LeaseVersion = 2
	denied := errors.New("synthetic failed inventory")
	for _, renew := range []bool{false, true} {
		calls, queries := 0, 0
		k := deploymentKernel{kernel: kernel{
			flowtableLookup: func(context.Context) error { queries++; return denied },
			run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
				calls++
				if input != "" || name != "nft" || len(args) != 7 || args[3] != "list" || args[4] != "table" || args[5] != "inet" || args[6] != leaseTable(entry) {
					t.Fatal("failed inventory reached fallback or mutation")
				}
				return json.Marshal(object{"nftables": stagedLeaseTestRows(entry, time.Unix(1, 0), "lease_00000000000000000000000000000001", "")})
			},
		}}
		now := time.Now()
		var err error
		if renew {
			_, err = k.Lease(context.Background(), entry, now.Add(time.Minute), FreshApproval{At: now})
		} else {
			_, err = k.LeaseStatus(context.Background(), entry)
		}
		wantReads := 0
		if renew {
			wantReads = 1
		}
		if !errors.Is(err, denied) || queries != 1 || calls != wantReads {
			t.Fatalf("denial lost: renew=%t queries=%d reads=%d", renew, queries, calls)
		}
	}
}
