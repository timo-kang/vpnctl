// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"vpnctl/internal/uplinkapi"
)

func uplinkAPIOptions(dir, uids string, apply, watch bool) (uplinkapi.Options, error) {
	options := uplinkapi.Options{Directory: dir}
	if dir == "" && uids == "" {
		return options, nil
	}
	invalid := errors.New("uplink API requires target reconcile --watch, canonical absolute --uplink-api-dir and 1..16 unique --uplink-api-allow-uids")
	if !apply || !watch || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" || len(uids) > 175 {
		return options, invalid
	}
	seen := map[uint32]bool{}
	for _, v := range strings.Split(uids, ",") {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != v || seen[uint32(n)] || len(seen) == 16 {
			return options, invalid
		}
		seen[uint32(n)] = true
		options.AllowedUIDs = append(options.AllowedUIDs, uint32(n))
	}
	return options, nil
}
