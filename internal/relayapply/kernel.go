// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"vpnctl/internal/relayplan"
)

const protocol = "186"

type object map[string]any
type kernel struct{ run commandFunc }
type snapshot struct {
	links, routes, rules []object
	marks                map[string]uint32
}

func num(v any) (uint32, bool) {
	switch x := v.(type) {
	case float64:
		if x >= 0 && x <= 4294967295 && x == float64(uint32(x)) {
			return uint32(x), true
		}
	case string:
		if x == "off" {
			return 0, true
		}
		base := 10
		if strings.HasPrefix(x, "0x") {
			base = 0
		}
		n, e := strconv.ParseUint(x, base, 32)
		return uint32(n), e == nil
	}
	return 0, false
}
func n(o object, key string) uint32   { v, _ := num(o[key]); return v }
func str(o object, key string) string { v, _ := o[key].(string); return v }
func decimal(n uint32) string         { return strconv.FormatUint(uint64(n), 10) }
func (k kernel) list(ctx context.Context, args ...string) ([]object, error) {
	b, err := k.run(ctx, "", "ip", args...)
	if err != nil {
		return nil, err
	}
	var rows []object
	if len(b) > 512<<10 || json.Unmarshal(b, &rows) != nil || rows == nil || len(rows) > 4096 {
		return nil, errors.New("invalid kernel inventory")
	}
	for _, r := range rows {
		if r == nil {
			return nil, errors.New("null kernel inventory")
		}
	}
	return rows, nil
}
func (k kernel) snapshot(ctx context.Context) (snapshot, error) {
	s := snapshot{marks: map[string]uint32{}}
	var err error
	s.links, err = k.list(ctx, "-j", "-N", "-d", "link", "show")
	if err != nil {
		return s, err
	}
	seen := map[string]bool{}
	for _, l := range s.links {
		name := str(l, "ifname")
		if name == "" || n(l, "ifindex") == 0 || seen[name] {
			return s, errors.New("invalid link inventory")
		}
		seen[name] = true
	}
	s.routes, err = k.list(ctx, "-j", "-N", "-4", "route", "show", "table", "all")
	if err != nil {
		return s, err
	}
	s.rules, err = k.list(ctx, "-j", "-N", "-4", "rule", "show")
	if err != nil {
		return s, err
	}
	for _, r := range s.routes {
		// iproute2 omits the table attribute for main even with -N/table all.
		if _, exists := r["table"]; !exists {
			r["table"] = float64(254)
		}
		if _, ok := num(r["table"]); !ok {
			return s, errors.New("route table not numeric")
		}
	}
	for _, r := range s.rules {
		if _, ok := num(r["priority"]); !ok {
			return s, errors.New("rule priority unavailable")
		}
	}
	b, err := k.run(ctx, "", "wg", "show", "all", "fwmark")
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return s, errors.New("invalid WG mark inventory")
		}
		mark, ok := num(f[1])
		if !ok || !seen[f[0]] {
			return s, errors.New("invalid WG mark")
		}
		if _, exists := s.marks[f[0]]; exists {
			return s, errors.New("duplicate WG mark")
		}
		s.marks[f[0]] = mark
	}
	return s, nil
}
func kind(o object) string {
	v, _ := o["linkinfo"].(map[string]any)
	s, _ := v["info_kind"].(string)
	return s
}
func hasFlag(o object, flag string) bool {
	v, _ := o["flags"].([]any)
	for _, s := range v {
		if s == flag {
			return true
		}
	}
	return false
}
func getLink(s snapshot, name string) (object, bool) {
	for _, l := range s.links {
		if str(l, "ifname") == name {
			return l, true
		}
	}
	return nil, false
}
func ownerLink(l object, e Entry) bool {
	// WireGuard ignores IFLA_IFALIAS during creation on supported kernels.
	// The requested ifindex and random group are installed atomically, so a
	// crash before the alias step still leaves an identifiable creation.
	return kind(l) == "wireguard" && n(l, "ifindex") == e.LinkIndex && n(l, "group") == e.Metric && (str(l, "ifalias") == e.Alias || e.Phase != "prepared" && str(l, "ifalias") == "")
}
func only(o object, keys ...string) bool {
	for key := range o {
		if !slices.Contains(keys, key) {
			return false
		}
	}
	return true
}
func routeMatches(o object, e Entry, guard bool) bool {
	p := e.Candidate.Pin
	if n(o, "table") != p.Table || n(o, "protocol") != 186 || n(o, "metric") != e.Metric {
		return false
	}
	if guard {
		return (str(o, "type") == "unreachable" || str(o, "type") == "7") && str(o, "dst") == "default" && only(o, "type", "dst", "table", "protocol", "metric", "scope", "flags")
	}
	if str(o, "type") != "" && str(o, "type") != "unicast" && str(o, "type") != "1" {
		return false
	}
	dst := str(o, "dst")
	if dst != p.EndpointPrefix && dst != strings.TrimSuffix(p.EndpointPrefix, "/32") {
		return false
	}
	return str(o, "dev") == p.Interface && str(o, "prefsrc") == p.Source && str(o, "gateway") == p.Gateway && only(o, "type", "dst", "table", "protocol", "metric", "scope", "flags", "dev", "prefsrc", "gateway")
}
func ruleMatches(o object, e Entry) bool {
	p := e.Candidate.Pin
	mask := ^uint32(0)
	if value, exists := o["fwmask"]; exists {
		var ok bool
		mask, ok = num(value)
		if !ok {
			return false
		}
	}
	return n(o, "priority") == p.RulePriority && n(o, "fwmark") == p.FWMark && mask == ^uint32(0) && n(o, "table") == p.Table && n(o, "protocol") == 186 && (str(o, "src") == "all" || str(o, "src") == "") && only(o, "priority", "src", "fwmark", "fwmask", "table", "protocol")
}
func markMatch(o object, mark uint32) bool {
	v, exists := o["fwmark"]
	if !exists {
		return true
	}
	m, ok := num(v)
	if !ok {
		return true
	}
	mask := ^uint32(0)
	if v, exists = o["fwmask"]; exists {
		var valid bool
		mask, valid = num(v)
		if !valid {
			return true
		}
	}
	match := mark&mask == m&mask
	if invert, _ := o["not"].(bool); invert {
		return !match
	}
	return match
}

// fresh refuses all preexisting candidate resources. Recovery only recognizes
// exact intent tuples, including the random link alias and route metric.
func conflicts(s snapshot, e Entry, fresh bool) error {
	p := e.Candidate.Pin
	for _, l := range s.links {
		if n(l, "ifindex") == e.LinkIndex && (fresh || str(l, "ifname") != p.WGInterface) {
			return ErrConflict
		}
	}
	if l, ok := getLink(s, p.WGInterface); ok && (fresh || !ownerLink(l, e)) {
		return ErrConflict
	}
	for iface, m := range s.marks {
		if m == p.FWMark && (iface != p.WGInterface || fresh) {
			return ErrConflict
		}
	}
	guards, endpoints, rules := 0, 0, 0
	for _, r := range s.routes {
		if n(r, "table") == 255 && n(r, "type") == 2 && str(r, "dst") == strings.TrimSuffix(e.Candidate.InnerAddress, "/32") && str(r, "dev") != p.WGInterface {
			return ErrConflict
		}
		if n(r, "table") == p.Table {
			if fresh {
				return ErrConflict
			}
			switch {
			case routeMatches(r, e, true):
				guards++
			case routeMatches(r, e, false):
				endpoints++
			default:
				return ErrConflict
			}
		}
		if str(r, "dev") == p.WGInterface && n(r, "table") != 255 {
			return ErrConflict
		} // no app routes owned here
	}
	for _, r := range s.rules {
		if !fresh && ruleMatches(r, e) {
			rules++
			continue
		}
		if n(r, "priority") == p.RulePriority || n(r, "table") == p.Table {
			return ErrConflict
		}
		// The builtin local lookup is allowed; every other earlier rule that
		// could capture this mark is conservatively rejected, including goto.
		local := n(r, "priority") == 0 && n(r, "table") == 255 && str(r, "src") == "all" && only(r, "priority", "src", "table", "protocol")
		if !local && n(r, "priority") < p.RulePriority && markMatch(r, p.FWMark) {
			return ErrConflict
		}
		if _, marked := r["fwmark"]; marked && markMatch(r, p.FWMark) {
			return ErrConflict
		}
	}
	if guards > 1 || endpoints > 1 || rules > 1 {
		return ErrConflict
	}
	return nil
}
func (k kernel) Check(ctx context.Context, e Entry, fresh bool) (bool, error) {
	s, err := k.snapshot(ctx)
	if err != nil {
		return false, err
	}
	if err = conflicts(s, e, fresh); err != nil {
		return false, err
	}
	if fresh {
		return false, nil
	}
	p := e.Candidate.Pin
	l, ok := getLink(s, p.WGInterface)
	if !ok {
		return false, nil
	}
	if !hasFlag(l, "UP") || n(l, "mtu") != 1280 || s.marks[p.WGInterface] != p.FWMark {
		return false, nil
	}
	guard, endpoint, rule := false, false, false
	for _, r := range s.routes {
		guard = guard || routeMatches(r, e, true)
		endpoint = endpoint || routeMatches(r, e, false)
	}
	for _, r := range s.rules {
		rule = rule || ruleMatches(r, e)
	}
	if !guard || !endpoint || !rule {
		return false, nil
	}
	return k.wireState(ctx, e, false)
}

// Partial creation may have none of the requested configuration yet. It may
// never have an extra address, peer, prefix or another public identity.
func (k kernel) wireState(ctx context.Context, e Entry, partial bool) (bool, error) {
	p := e.Candidate.Pin
	addresses, err := k.list(ctx, "-j", "address", "show", "dev", p.WGInterface)
	if err != nil {
		return false, err
	}
	if len(addresses) != 1 {
		return false, ErrConflict
	}
	addr, complete := addresses[0]["addr_info"].([]any)
	if !complete || addr == nil || len(addr) > 16 {
		return false, errors.New("incomplete candidate address inventory")
	}
	got := []string{}
	for _, a := range addr {
		r, ok := a.(map[string]any)
		if !ok {
			return false, ErrConflict
		}
		if str(r, "family") == "inet" {
			got = append(got, str(r, "local")+"/"+decimal(n(r, "prefixlen")))
		} else if str(r, "family") != "inet6" || str(r, "scope") != "link" {
			return false, ErrConflict
		}
	}
	if !(partial && len(got) == 0) && (len(got) != 1 || got[0] != e.Candidate.InnerAddress) {
		return false, ErrConflict
	}
	checks := []struct{ field, want string }{{"public-key", e.Candidate.PublicKey}, {"peers", e.Candidate.RelayPublicKey}, {"endpoints", e.Candidate.RelayPublicKey + " " + e.Candidate.Endpoint}, {"allowed-ips", e.Candidate.RelayPublicKey + " " + strings.Join(prefixes(e), " ")}, {"persistent-keepalive", e.Candidate.RelayPublicKey + " off"}}
	for _, check := range checks {
		b, err := k.run(ctx, "", "wg", "show", p.WGInterface, check.field)
		if err != nil {
			return false, err
		}
		got := strings.Join(strings.Fields(strings.ReplaceAll(string(b), ",", " ")), " ")
		if check.field == "allowed-ips" {
			f := strings.Fields(got)
			if len(f) > 1 {
				slices.Sort(f[1:])
				got = strings.Join(f, " ")
			}
		}
		if partial && (got == "" || check.field == "public-key" && got == "(none)" || (check.field == "allowed-ips" || check.field == "endpoints") && got == e.Candidate.RelayPublicKey+" (none)") {
			continue
		}
		if partial && check.field == "allowed-ips" {
			f := strings.Fields(got)
			if len(f) > 0 && f[0] == e.Candidate.RelayPublicKey {
				valid := true
				for _, prefix := range f[1:] {
					valid = valid && slices.Contains(prefixes(e), prefix)
				}
				if valid {
					continue
				}
			}
		}
		if got != check.want {
			return false, ErrConflict
		}
	}
	return true, nil
}

func routeArgs(e Entry, verb string, guard bool) []string {
	p := e.Candidate.Pin
	a := []string{"-4", "route", verb}
	if guard {
		a = append(a, "unreachable", "default")
	} else {
		a = append(a, p.EndpointPrefix)
		if p.Gateway != "" {
			a = append(a, "via", p.Gateway, "onlink")
		}
		a = append(a, "dev", p.Interface, "src", p.Source)
	}
	return append(a, "table", decimal(p.Table), "proto", protocol, "metric", decimal(e.Metric))
}
func ruleArgs(e Entry, verb string) []string {
	p := e.Candidate.Pin
	return []string{"-4", "rule", verb, "priority", decimal(p.RulePriority), "fwmark", decimal(p.FWMark) + "/0xffffffff", "lookup", decimal(p.Table), "protocol", protocol}
}
func (k kernel) Step(ctx context.Context, e Entry, step, key string) error {
	p := e.Candidate.Pin
	s, err := k.snapshot(ctx)
	if err != nil {
		return err
	}
	if err = conflicts(s, e, step == "link"); err != nil {
		return err
	}
	if step != "link" {
		l, ok := getLink(s, p.WGInterface)
		if !ok || !ownerLink(l, e) {
			return ErrConflict
		}
		if mark := s.marks[p.WGInterface]; mark != 0 && mark != p.FWMark {
			return ErrConflict
		}
		if _, err = k.wireState(ctx, e, true); err != nil {
			return err
		}
	}
	var args []string
	name, input := "ip", ""
	switch step {
	case "link":
		args = []string{"link", "add", "name", p.WGInterface, "index", decimal(e.LinkIndex), "group", decimal(e.Metric), "mtu", "1280", "type", "wireguard"}
	case "tag":
		args = []string{"link", "set", "dev", p.WGInterface, "alias", e.Alias}
	case "guard":
		args = routeArgs(e, "add", true)
	case "endpoint":
		args = routeArgs(e, "add", false)
	case "rule":
		args = ruleArgs(e, "add")
	case "address":
		args = []string{"-4", "address", "add", e.Candidate.InnerAddress, "dev", p.WGInterface, "noprefixroute"}
	case "wg":
		name = "wg"
		args = []string{"setconf", p.WGInterface, "/dev/stdin"}
		input = fmt.Sprintf("[Interface]\nPrivateKey = %s\nFwMark = %d\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 0\n", key, p.FWMark, e.Candidate.RelayPublicKey, e.Candidate.Endpoint, strings.Join(prefixes(e), ","))
	case "up":
		args = []string{"link", "set", "dev", p.WGInterface, "up"}
	default:
		return errors.New("invalid apply step")
	}
	_, err = k.run(ctx, input, name, args...)
	return err
}
func (k kernel) Remove(ctx context.Context, e Entry) error {
	// Stop the WG socket before deleting its guard. Reinspect before every
	// removal; a partial cleanup remains recoverable from the original intent.
	for _, step := range []string{"link", "rule", "endpoint", "guard"} {
		s, err := k.snapshot(ctx)
		if err != nil {
			return err
		}
		if err = conflicts(s, e, false); err != nil {
			return err
		}
		var args []string
		switch step {
		case "link":
			if _, ok := getLink(s, e.Candidate.Pin.WGInterface); ok {
				if mark := s.marks[e.Candidate.Pin.WGInterface]; mark != 0 && mark != e.Candidate.Pin.FWMark {
					return ErrConflict
				}
				if _, err = k.wireState(ctx, e, true); err != nil {
					return err
				}
				args = []string{"link", "del", "dev", e.Candidate.Pin.WGInterface}
			}
		case "rule":
			for _, r := range s.rules {
				if ruleMatches(r, e) {
					args = ruleArgs(e, "del")
				}
			}
		case "endpoint", "guard":
			for _, r := range s.routes {
				if routeMatches(r, e, step == "guard") {
					args = routeArgs(e, "del", step == "guard")
				}
			}
		}
		if args != nil {
			if _, err = k.run(ctx, "", "ip", args...); err != nil {
				return err
			}
		}
	}
	s, err := k.snapshot(ctx)
	if err != nil {
		return err
	}
	return conflicts(s, e, true)
}

func inventoryMatches(ctx context.Context, e Entry, underlays []relayplan.Underlay, c relayplan.Collector) error {
	if c == nil {
		c = relayplan.LinuxCollector{}
	}
	for _, u := range underlays {
		if u.ID != e.Candidate.UnderlayID {
			continue
		}
		v := c.Collect(ctx, u, []string{e.Candidate.Endpoint})
		p := e.Candidate.Pin
		age := time.Since(v.ObservedAt)
		if v.State != "up" || v.Present == nil || !*v.Present || v.AdminUp == nil || !*v.AdminUp || v.Carrier == nil || !*v.Carrier || v.Underlay != u || v.Interface != p.Interface || v.IfIndex != p.IfIndex || v.ObservedAt.IsZero() || age < 0 || age > relayplan.MaxAge || !slices.Contains(v.Addresses, p.Source) || len(v.Routes) != 1 {
			return errors.New("underlay changed")
		}
		r := v.Routes[0]
		if r.State != "up" || r.Endpoint != e.Candidate.Endpoint || r.Source != p.Source || r.Gateway != p.Gateway {
			return errors.New("endpoint route changed")
		}
		return nil
	}
	return errors.New("underlay mapping missing")
}
