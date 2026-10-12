// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Go's test cache cannot observe files opened by a Python subprocess.
	// Track the source dependencies in the parent before invoking the suite.
	files, err := filepath.Glob("../../examples/uplink/python/*.py")
	if err != nil || len(files) == 0 {
		os.Exit(2)
	}
	for _, file := range files {
		if _, err := os.ReadFile(file); err != nil {
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}
