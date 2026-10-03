// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package wireguard

import (
	"os"
	"path/filepath"
	"testing"
	"vpnctl/internal/config"
)

func TestInterfaceOwnerRejectsAllWritersBeforeMutation(t *testing.T) {
	iface := "test-owned"
	unlock, err := LockInterface(iface)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	path := filepath.Join(t.TempDir(), "wg.conf")
	if err = os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	rr := &recordRunner{}
	m := NewManager(rr)
	cfg := config.NodeConfig{WGInterface: iface, WGConfigPath: path, VPNIP: "10.7.0.2/32"}
	calls := []func() error{
		func() error { return m.Up(cfg, "new") },
		func() error { return m.UpConfigured(cfg, "new-file", "new") },
		func() error { return m.Down(cfg) },
		func() error { return m.ApplyPeers(cfg, nil) },
	}
	for _, call := range calls {
		if err := call(); err == nil {
			t.Fatal("concurrent writer admitted")
		}
	}
	if len(rr.cmds) != 0 {
		t.Fatal(rr.cmds)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "original" {
		t.Fatal("rejected writer changed config")
	}
	unlock()
	again, err := LockInterface(iface)
	if err != nil {
		t.Fatal(err)
	}
	again()
}
