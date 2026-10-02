// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUnsafePinRoot(t *testing.T) {
	root := t.TempDir()
	safe := filepath.Join(root, "owned")
	if err := os.Mkdir(safe, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(safe, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{safe, alias, filepath.Join(root, "missing"), "relative", "/"} {
		t.Setenv("VPNCTL_BPF_ROOT", path)
		f, err := pinDirectory()
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatalf("non-bpffs/unsafe root accepted: %s", path)
		}
	}
}
