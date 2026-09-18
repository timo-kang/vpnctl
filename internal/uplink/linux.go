// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"vpnctl/internal/execx"
)

type LinuxCollector struct{ Runner execx.ContextRunner }

func (c LinuxCollector) runner() execx.ContextRunner {
	if c.Runner != nil {
		return c.Runner
	}
	return optionalRunner{}
}
func (c LinuxCollector) Collect(ctx context.Context, cfg LinkConfig) Link {
	l := Link{ID: cfg.ID, Interface: cfg.Interface, Kind: cfg.Kind, Check: Unknown("collector_unavailable"), Modem: Unknown("not_configured"), DNS: Unknown("resolver_unavailable"), GatewayState: Unknown("gateway_unavailable")}
	r := c.runner()
	if cfg.Kind == "lte" && cfg.Modem != "" {
		l.Modem = collectModem(ctx, r, cfg.Modem)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return l
	}
	present := false
	l.Present = &present
	for _, iface := range interfaces {
		if iface.Name != cfg.Interface {
			continue
		}
		present = true
		addrs, e := iface.Addrs()
		if e != nil {
			return l
		}
		routable := false
		for _, a := range addrs {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil && len(l.Addresses) < 16 {
				l.Addresses = append(l.Addresses, a.String())
				if ip.IsGlobalUnicast() {
					routable = true
				}
			}
		}
		switch {
		case iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0:
			l.Check = Down("link_down")
		case !routable:
			l.Check = Down("no_ip")
		default:
			l.Check = Up()
		}
		break
	}
	if !present {
		l.Check = Down("interface_absent")
	}
	if l.Modem.State == "down" && l.State != "up" {
		l.Reason = l.Modem.Reason
	}
	gatewayReads := 0
	for _, family := range []string{"-4", "-6"} {
		out, e := r.OutputContext(ctx, "ip", family, "-j", "route", "show", "default", "dev", cfg.Interface)
		if e != nil {
			continue
		}
		var routes []struct {
			Gateway string `json:"gateway"`
		}
		if json.Unmarshal([]byte(out), &routes) != nil {
			continue
		}
		gatewayReads++
		for _, route := range routes {
			if net.ParseIP(route.Gateway) != nil && len(l.Gateways) < 16 {
				l.Gateways = append(l.Gateways, route.Gateway)
			}
		}
	}
	if len(l.Gateways) > 0 {
		l.GatewayState = Up()
	} else if gatewayReads == 2 {
		l.GatewayState = Down("no_default_gateway")
	}
	// systemd-resolved's per-link configuration; do not misattribute the host's
	// /etc/resolv.conf (often a loopback stub) to every individual interface.
	if out, e := r.OutputContext(ctx, "resolvectl", "dns", cfg.Interface); e == nil {
		l.DNS = Down("no_dns_configured")
		if _, values, ok := strings.Cut(out, ":"); ok {
			for _, v := range strings.Fields(values) {
				if net.ParseIP(v) != nil {
					l.DNS = Up()
					l.DNS.Reason = "configured"
					break
				}
			}
		}
	}
	return l
}
func keyValues(out string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			values[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return values
}
func collectModem(ctx context.Context, r execx.ContextRunner, index string) Check {
	out, e := r.OutputContext(ctx, "mmcli", "--list-modems", "--output-keyvalue")
	if e != nil {
		return Unknown("modem_collector_unavailable")
	}
	values := keyValues(out)
	count, e := strconv.Atoi(values["modem-list.length"])
	if e != nil || count < 0 || count > 256 {
		return Unknown("modem_output_invalid")
	}
	found := false
	for i := 1; i <= count; i++ {
		if values["modem-list.value["+strconv.Itoa(i)+"]"] == "/org/freedesktop/ModemManager1/Modem/"+index {
			found = true
		}
	}
	if !found {
		return Down("no_modem")
	}
	out, e = r.OutputContext(ctx, "mmcli", "--modem", index, "--output-keyvalue")
	if e != nil {
		return Unknown("modem_collector_unavailable")
	}
	switch keyValues(out)["modem.generic.state"] {
	case "connected":
		return Up()
	case "registered", "connecting", "disconnecting":
		return Down("modem_no_data")
	case "failed", "disabled", "disabling", "enabling", "enabled", "locked", "searching", "initializing":
		return Down("modem_no_service")
	default:
		return Unknown("modem_state_unknown")
	}
}

// Expected missing optional executables should not create repeated warning logs.
type optionalRunner struct{ execx.OSRunner }

func (r optionalRunner) OutputContext(ctx context.Context, name string, args ...string) (string, error) {
	if name == "mmcli" || name == "resolvectl" {
		if _, err := exec.LookPath(name); err != nil {
			return "", err
		}
	}
	return r.OSRunner.OutputContext(ctx, name, args...)
}
func (r optionalRunner) RunContext(ctx context.Context, name string, args ...string) error {
	return r.OSRunner.RunContext(ctx, name, args...)
}
