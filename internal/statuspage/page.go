// Copyright 2025 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package statuspage

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed index.html
var content embed.FS

var tmpl = template.Must(template.ParseFS(content, "index.html"))

// Data is passed to the status page template.
type Data struct {
	Title       string
	Nodes       []NodeStatus
	OnlineCount int
	TotalCount  int
}

// NodeStatus represents one node in the status page.
type NodeStatus struct {
	Name    string
	VPNIP   string
	NATType string
	LastSeen string
	Online  bool
	Quality string // good, degraded, poor, offline
	RTTMs   string
	LossPct string
}

// Handler returns an http.HandlerFunc that renders the status page.
func Handler(dataFn func() Data) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := dataFn()
		if data.Title == "" {
			data.Title = "vpnctl"
		}
		_ = tmpl.Execute(w, data)
	}
}
