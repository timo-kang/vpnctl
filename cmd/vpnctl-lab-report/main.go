// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"vpnctl/internal/labreport"
)

func main() { os.Exit(run()) }
func run() int {
	dir := flag.String("dir", "", "one m2-soak output directory (read only)")
	manifest := flag.String("manifest", "", "runner manifest (read only)")
	exitFile := flag.String("exit-file", "", "independently recorded integer process exit code; omitted for progress")
	flag.Parse()
	if *dir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--dir required; positional arguments not accepted")
		return 1
	}
	var status *int
	if *exitFile != "" {
		f, e := os.Open(*exitFile)
		if e != nil {
			fmt.Fprintln(os.Stderr, "exit record unavailable")
			return 1
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 32))
		if e != nil || len(b) == 32 {
			fmt.Fprintln(os.Stderr, "invalid exit record")
			return 1
		}
		v, e := strconv.Atoi(strings.TrimSpace(string(b)))
		if e != nil || v < 0 || v > 255 {
			fmt.Fprintln(os.Stderr, "invalid exit code")
			return 1
		}
		status = &v
	}
	r := labreport.Analyze(*dir, *manifest, status)
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	if e := out.Encode(r); e != nil {
		return 1
	}
	switch r.Status {
	case "complete":
		return 0
	case "incomplete":
		return 2
	default:
		return 1
	}
}
