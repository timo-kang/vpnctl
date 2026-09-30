// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func kernelFixture(t *testing.T) (Entry, snapshot) {
	t.Helper()
	e, _, _ := fixture(t, "robot")
	entry, _, err := e.approval(context.Background(), "p0", "")
	if err != nil {
		t.Fatal(err)
	}
	entry.Alias, entry.Metric, entry.LinkIndex, err = token()
	if err != nil {
		t.Fatal(err)
	}
	p := entry.Candidate.Pin
	s := snapshot{marks: map[string]uint32{p.WGInterface: p.FWMark}, links: []object{{"ifname": p.WGInterface, "ifindex": float64(entry.LinkIndex), "group": decimal(entry.Metric), "ifalias": entry.Alias, "linkinfo": map[string]any{"info_kind": "wireguard"}}}, routes: []object{{"type": "7", "dst": "default", "table": decimal(p.Table), "protocol": "186", "metric": float64(entry.Metric), "flags": []any{}}, {"dst": strings.TrimSuffix(p.EndpointPrefix, "/32"), "dev": p.Interface, "prefsrc": p.Source, "table": decimal(p.Table), "protocol": "186", "metric": float64(entry.Metric), "flags": []any{}}}, rules: []object{{"priority": float64(0), "src": "all", "table": "255"}, {"priority": float64(p.RulePriority), "src": "all", "fwmark": "0x" + strings.TrimPrefix(hexMark(p.FWMark), "0x"), "table": decimal(p.Table), "protocol": "186"}, {"priority": float64(32766), "src": "all", "table": "254"}}}
	return entry, s
}
func hexMark(n uint32) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = digits[n&15]
		n >>= 4
	}
	return "0x" + string(b)
}
func TestResourceConflicts(t *testing.T) {
	for _, mode := range []string{"clean", "no-alias-before-tag", "wrong-index", "wrong-group", "wrong-alias", "renamed-owned", "foreign-route", "changed-metric", "duplicate-guard", "foreign-rule", "duplicate-rule", "overlapping-mask", "earlier-catchall", "earlier-not", "foreign-wg-mark", "extra-route-field", "extra-rule-selector", "malformed-mask", "existing-inner-address"} {
		t.Run(mode, func(t *testing.T) {
			e, s := kernelFixture(t)
			p := e.Candidate.Pin
			switch mode {
			case "no-alias-before-tag":
				delete(s.links[0], "ifalias")
			case "wrong-index":
				s.links[0]["ifindex"] = float64(e.LinkIndex + 1)
			case "wrong-group":
				s.links[0]["group"] = "20"
			case "wrong-alias":
				s.links[0]["ifalias"] = "external"
			case "renamed-owned":
				s.links[0]["ifname"] = "renamed"
			case "foreign-route":
				s.routes = append(s.routes, object{"dst": "203.0.113.0/24", "table": decimal(p.Table), "protocol": "4"})
			case "changed-metric":
				s.routes[0]["metric"] = float64(e.Metric + 1)
			case "duplicate-guard":
				s.routes = append(s.routes, s.routes[0])
			case "foreign-rule":
				s.rules[1]["protocol"] = "4"
			case "duplicate-rule":
				s.rules = append(s.rules, s.rules[1])
			case "overlapping-mask":
				s.rules = append(s.rules, object{"priority": float64(100), "fwmark": "0x76000000", "fwmask": "0xff000000", "table": "100"})
			case "earlier-catchall":
				s.rules = append(s.rules, object{"priority": float64(100), "src": "all", "table": "100"})
			case "earlier-not":
				s.rules = append(s.rules, object{"priority": float64(100), "src": "all", "not": true, "fwmark": "1", "table": "100"})
			case "foreign-wg-mark":
				s.marks["external"] = p.FWMark
			case "extra-route-field":
				s.routes[1]["nhid"] = float64(4)
			case "extra-rule-selector":
				s.rules[1]["iif"] = "other"
			case "malformed-mask":
				s.rules[1]["fwmask"] = "invalid"
			case "existing-inner-address":
				s.routes = append(s.routes, object{"table": "255", "type": "2", "dst": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "dev": "other"})
			}
			err := conflicts(s, e, false)
			want := mode != "clean" && mode != "no-alias-before-tag"
			if (err != nil) != want {
				t.Fatal(mode, err)
			}
			if err = conflicts(s, e, true); err == nil {
				t.Fatal("fresh apply adopted resources")
			}
		})
	}
}
func TestKernelInventoryRejectsMalformedAndOversized(t *testing.T) {
	for _, raw := range []string{"null", "{}", "[null]", "[{}]", strings.Repeat(" ", 513<<10)} {
		t.Run(strings.TrimSpace(raw)[:min(8, len(strings.TrimSpace(raw)))], func(t *testing.T) {
			k := kernel{run: func(context.Context, string, string, ...string) ([]byte, error) { return []byte(raw), nil }}
			if _, err := k.snapshot(context.Background()); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}
func TestKernelCommandBoundsAndSecretErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := command(ctx, "", "sh", "-c", "sleep 10"); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatal("timeout", err)
	}
	for _, script := range []string{"printf private_key >&2; exit 1", "head -c 600000 /dev/zero", "head -c 5000 /dev/zero >&2"} {
		_, err := command(context.Background(), "secret-private-key", "sh", "-c", script)
		if err == nil || strings.Contains(err.Error(), "private_key") || strings.Contains(err.Error(), "secret-private-key") {
			t.Fatal("unbounded or unsafe command error", err)
		}
	}
}
func TestWGExtraPeerRefusesRemoval(t *testing.T) {
	e, s := kernelFixture(t)
	p := e.Candidate.Pin
	mutations := 0
	k := kernel{run: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		var out any
		switch {
		case joined == "-j -N -d link show":
			out = s.links
		case joined == "-j -N -4 route show table all":
			out = s.routes
		case joined == "-j -N -4 rule show":
			out = s.rules
		case joined == "show all fwmark":
			return []byte(p.WGInterface + " " + decimal(p.FWMark)), nil
		case strings.Contains(joined, "address show"):
			out = []object{{"addr_info": []object{{"family": "inet", "local": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "prefixlen": 32}}}}
		case strings.HasSuffix(joined, "public-key"):
			return []byte(e.Candidate.PublicKey), nil
		case strings.HasSuffix(joined, " peers"):
			return []byte(e.Candidate.RelayPublicKey + "\n" + public("unrelated")), nil
		default:
			mutations++
			return nil, errors.New("unexpected mutation " + name)
		}
		return json.Marshal(out)
	}}
	if err := k.Remove(context.Background(), e); !errors.Is(err, ErrConflict) || mutations > 0 {
		t.Fatal("modified interface removed", err, mutations)
	}
}

func TestWGUnapprovedPresharedKey(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, extra := range []bool{false, true} {
			e, _ := kernelFixture(t)
			secret := "unapproved-secret"
			k := kernel{run: func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "address show") {
					return json.Marshal([]object{{"addr_info": []object{{"family": "inet", "local": strings.TrimSuffix(e.Candidate.InnerAddress, "/32"), "prefixlen": 32}}}})
				}
				values := map[string]string{
					"public-key":           e.Candidate.PublicKey,
					"peers":                e.Candidate.RelayPublicKey,
					"endpoints":            e.Candidate.RelayPublicKey + " " + e.Candidate.Endpoint,
					"allowed-ips":          e.Candidate.RelayPublicKey + " " + strings.Join(prefixes(e), " "),
					"persistent-keepalive": e.Candidate.RelayPublicKey + " off",
					"preshared-keys":       e.Candidate.RelayPublicKey + " (none)",
				}
				if extra {
					values["preshared-keys"] = e.Candidate.RelayPublicKey + " " + secret
				}
				return []byte(values[args[len(args)-1]]), nil
			}}
			ready, err := k.wireState(context.Background(), e, partial)
			if extra && (!errors.Is(err, ErrConflict) || ready) || !extra && (err != nil || !ready) {
				t.Fatalf("partial=%v extra=%v ready=%v err=%v", partial, extra, ready, err)
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatal("preshared key leaked into error")
			}
		}
	}
}
