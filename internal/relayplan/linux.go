// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"
)

var errNoRoute = errors.New("endpoint unreachable")
var errOutputLimit = errors.New("inventory output exceeds limit")

type LinuxCollector struct {
	// ReadIP is injectable; implementations must honor context and output limits.
	ReadIP func(context.Context, ...string) ([]byte, error)
}
type cappedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

// Do not embed bytes.Buffer: its promoted ReadFrom would bypass Write in io.Copy.
func (b *cappedBuffer) Len() int       { return b.buffer.Len() }
func (b *cappedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *cappedBuffer) String() string { return b.buffer.String() }
func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errOutputLimit
	}
	return b.buffer.Write(p)
}
func readIP(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, stderr := &cappedBuffer{limit: MaxOutputBytes}, &cappedBuffer{limit: 4096}
	cmd := exec.CommandContext(ctx, "ip", args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdout, cmd.Stderr = out, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(e, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.WaitDelay = 250 * time.Millisecond
	if e := cmd.Run(); e != nil {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(e, errOutputLimit) {
			return nil, errOutputLimit
		}
		var exit *exec.ExitError
		if errors.As(e, &exit) && exit.ExitCode() == 2 && (strings.TrimSpace(stderr.String()) == "RTNETLINK answers: Network is unreachable" || strings.TrimSpace(stderr.String()) == "RTNETLINK answers: No route to host") {
			return nil, errNoRoute
		}
		return nil, errors.New("inventory command failed")
	}
	return out.Bytes(), nil
}

type addressRecord struct {
	Family            string          `json:"family"`
	Local             string          `json:"local"`
	PrefixLen         int             `json:"prefixlen"`
	Scope             string          `json:"scope"`
	Flags             []string        `json:"flags"`
	Deprecated        bool            `json:"deprecated"`
	Tentative         bool            `json:"tentative"`
	DADFailed         bool            `json:"dadfailed"`
	ValidLifetime     json.RawMessage `json:"valid_life_time"`
	PreferredLifetime json.RawMessage `json:"preferred_life_time"`
}
type linkRecord struct {
	Index     int             `json:"ifindex"`
	Name      string          `json:"ifname"`
	Flags     []string        `json:"flags"`
	OperState string          `json:"operstate"`
	Addresses []addressRecord `json:"addr_info"`
}

func (c LinuxCollector) read(ctx context.Context, args ...string) ([]byte, error) {
	read := c.ReadIP
	if read == nil {
		read = readIP
	}
	b, e := read(ctx, args...)
	if len(b) > MaxOutputBytes {
		return nil, errOutputLimit
	}
	return b, e
}
func (c LinuxCollector) link(ctx context.Context, name string) (linkRecord, bool, error) {
	b, e := c.read(ctx, "-j", "address", "show")
	if e != nil {
		return linkRecord{}, false, e
	}
	var links []linkRecord
	if json.Unmarshal(b, &links) != nil || links == nil || len(links) > MaxInterfaces {
		return linkRecord{}, false, errors.New("invalid inventory")
	}
	var found linkRecord
	present := false
	names, indexes := map[string]bool{}, map[int]bool{}
	for _, l := range links {
		if l.Name == "" || len(l.Name) > 15 || l.Index <= 0 || l.Flags == nil || names[l.Name] || indexes[l.Index] {
			return linkRecord{}, false, errors.New("invalid inventory")
		}
		names[l.Name], indexes[l.Index] = true, true
		if l.Name != name {
			continue
		}
		if present || l.Index <= 0 || l.Flags == nil || l.Addresses == nil || len(l.Addresses) > MaxAddresses {
			return linkRecord{}, false, errors.New("invalid inventory")
		}
		found, present = l, true
	}
	return found, present, nil
}
func zeroLifetime(b json.RawMessage) bool { return string(b) == "0" || string(b) == `"0"` }
func ipv4Addresses(l linkRecord) ([]string, error) {
	v := []string{}
	for _, a := range l.Addresses {
		if a.Family != "inet" {
			continue
		}
		if _, e := netip.ParseAddr(a.Local); e != nil {
			return nil, errors.New("invalid address encoding")
		}
		if !usableIPv4(a.Local) || a.Deprecated || a.Tentative || a.DADFailed || a.Scope != "global" || slices.Contains(a.Flags, "tentative") || slices.Contains(a.Flags, "dadfailed") || slices.Contains(a.Flags, "deprecated") || zeroLifetime(a.ValidLifetime) || zeroLifetime(a.PreferredLifetime) {
			continue
		}
		if a.PrefixLen < 0 || a.PrefixLen > 32 || slices.Contains(v, a.Local) {
			return nil, errors.New("invalid IPv4 address inventory")
		}
		v = append(v, a.Local)
	}
	slices.Sort(v)
	return v, nil
}
func (c LinuxCollector) Collect(ctx context.Context, u Underlay, endpoints []string) Inventory {
	v := Inventory{Underlay: u, Check: unknown("collector_unavailable"), Addresses: []string{}, Routes: []Route{}, DNS: unknown("not_collected"), Modem: unknown("not_collected")}
	if ValidateUnderlays([]Underlay{u}) != nil || len(endpoints) > 8 {
		v.Check = unknown("invalid_request")
		return v
	}
	// Each collector is bounded even when used outside Build. Build also imposes
	// one deadline across all devices, with no background goroutines or retries.
	ctx, cancel := context.WithTimeout(ctx, MaxDuration)
	defer cancel()
	l, present, e := c.link(ctx, u.Interface)
	v.ObservedAt = time.Now().UTC()
	if e != nil {
		return v
	}
	v.Present = &present
	if !present {
		v.Check = down("interface_absent")
		return v
	}
	v.IfIndex = l.Index
	up, carrier := slices.Contains(l.Flags, "UP"), slices.Contains(l.Flags, "LOWER_UP")
	v.AdminUp, v.Carrier = &up, &carrier
	if !up || !carrier {
		v.Check = down("link_down")
		return v
	}
	v.Addresses, e = ipv4Addresses(l)
	if e != nil {
		v.Check = unknown("address_inventory_invalid")
		return v
	}
	if len(v.Addresses) == 0 {
		v.Check = down("no_ipv4")
		return v
	}
	source := u.SourceIPv4
	if source == "" {
		if len(v.Addresses) != 1 {
			v.Check = unknown("source_ambiguous")
			return v
		}
		source = v.Addresses[0]
	} else if !slices.Contains(v.Addresses, source) {
		v.Check = down("source_absent")
		return v
	}
	v.Check = Check{State: "up"}
	for _, ep := range endpoints {
		route := Route{Check: unknown("route_unavailable"), Endpoint: ep}
		ap, e := netip.ParseAddrPort(ep)
		if e != nil || !usableIPv4(ap.Addr().String()) || ap.Port() == 0 {
			v.Check = unknown("invalid_endpoint")
			return v
		}
		b, e := c.read(ctx, "-j", "-4", "route", "get", ap.Addr().String(), "from", source, "oif", u.Interface)
		if errors.Is(e, errNoRoute) {
			route.Check = down("endpoint_unreachable")
		} else if e == nil {
			var routes []struct {
				Dev             string `json:"dev"`
				Destination     string `json:"dst"`
				Source          string `json:"from"`
				PreferredSource string `json:"prefsrc"`
				Gateway         string `json:"gateway"`
				Type            string `json:"type"`
			}
			if json.Unmarshal(b, &routes) == nil && len(routes) == 1 {
				r := routes[0]
				selected := r.Source
				if selected == "" {
					selected = r.PreferredSource
				}
				if r.Dev == u.Interface && r.Destination == ap.Addr().String() && selected == source && (r.Type == "" || r.Type == "unicast") && (r.Gateway == "" || usableIPv4(r.Gateway)) {
					route.Check = Check{State: "up"}
					route.Source, route.Gateway = source, r.Gateway
				}
			}
		}
		v.Routes = append(v.Routes, route)
	}
	// Detect deletion/recreation, rename and address changes during the reads.
	after, present, e := c.link(ctx, u.Interface)
	if e != nil || !present || !sameLink(l, after) {
		v.Check = unknown("inventory_changed")
		v.Routes = nil
	}
	return v
}
func sameLink(a, b linkRecord) bool {
	// Lifetimes count down during collection; compare stable selection inputs.
	aa, ea := ipv4Addresses(a)
	bb, eb := ipv4Addresses(b)
	return ea == nil && eb == nil && a.Index == b.Index && a.Name == b.Name && slices.Equal(a.Flags, b.Flags) && a.OperState == b.OperState && reflect.DeepEqual(aa, bb) && reflect.DeepEqual(stableAddresses(a), stableAddresses(b))
}

var _ io.Writer = (*cappedBuffer)(nil)

func stableAddresses(l linkRecord) []addressRecord {
	v := []addressRecord{}
	for _, a := range l.Addresses {
		if a.Family == "inet" {
			a.ValidLifetime = nil
			a.PreferredLifetime = nil
			v = append(v, a)
		}
	}
	return v
}
