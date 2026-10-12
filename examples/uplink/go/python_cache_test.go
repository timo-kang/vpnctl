// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Include subprocess source files in Go test-cache dependencies.
	files, err := filepath.Glob("../python/*.py")
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
