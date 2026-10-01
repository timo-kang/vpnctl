// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRelayDeploymentKernelInventoryAndForeignState(t *testing.T) {
	for _, mode := range []string{"clean", "kernel-multicast", "foreign-v6", "foreign-v6-multicast", "foreign-address", "wrong-key", "wrong-port", "wrong-mark", "extra-peer", "extra-allowed-ip", "psk", "keepalive", "wrong-owner", "route-metric", "route-extra", "missing-route", "missing-peer", "link-down", "port-collision"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, _, o, _ := deploymentFixture(t, 1)
			r, err := e.cache.Status()
			if err != nil {
				t.Fatal(err)
			}
			v, err := desiredDeployment(r, o.EndpointID, o.ListenPort)
			if err != nil {
				t.Fatal(err)
			}
			v.Alias, v.Group, v.LinkIndex, err = token()
			if err != nil {
				t.Fatal(err)
			}
			v.Phase = "applied"
			link := object{"ifname": v.Interface, "ifindex": v.LinkIndex, "group": v.Group, "ifalias": v.Alias, "mtu": 1280, "flags": []string{"UP"}, "linkinfo": object{"info_kind": "wireguard"}}
			routes := []object{}
			fields := map[string]string{"public-key": v.PublicKey, "listen-port": "51820", "fwmark": "off"}
			for _, p := range v.Peers {
				routes = append(routes, object{"dst": strings.TrimSuffix(p.Address, "/32"), "dev": v.Interface, "protocol": "186", "scope": "253", "metric": v.Group, "flags": []string{}})
				fields["peers"] += p.PublicKey + "\n"
				fields["allowed-ips"] += p.PublicKey + " " + p.Address + "\n"
				fields["preshared-keys"] += p.PublicKey + " (none)\n"
				fields["persistent-keepalive"] += p.PublicKey + " off\n"
			}
			addresses := []object{}
			v6 := []object{}
			listeners := v.Interface + " 51820"
			switch mode {
			case "kernel-multicast", "foreign-v6-multicast":
				v6 = append(v6, object{"dst": "ff00::/8", "dev": v.Interface, "table": "255", "type": "5", "protocol": "2", "metric": 256, "flags": []string{}, "pref": "medium"})
				if mode == "foreign-v6-multicast" {
					v6[0]["protocol"] = "4"
				}
			case "foreign-v6":
				v6 = append(v6, object{"dst": "2001:db8::/64", "dev": v.Interface, "protocol": "4"})
			case "foreign-address":
				addresses = append(addresses, object{"family": "inet", "local": "203.0.113.1", "scope": "global"})
			case "wrong-key":
				fields["public-key"] = public("other-relay")
			case "wrong-port":
				fields["listen-port"] = "51900"
			case "wrong-mark":
				fields["fwmark"] = "42"
			case "extra-peer":
				fields["peers"] += public("external") + "\n"
			case "extra-allowed-ip":
				fields["allowed-ips"] = strings.ReplaceAll(fields["allowed-ips"], "/32", "/32 0.0.0.0/0")
			case "psk":
				fields["preshared-keys"] = strings.ReplaceAll(fields["preshared-keys"], "(none)", "must-not-disclose")
			case "keepalive":
				fields["persistent-keepalive"] = strings.ReplaceAll(fields["persistent-keepalive"], "off", "25")
			case "wrong-owner":
				link["ifalias"] = "external"
			case "route-metric":
				routes[0]["metric"] = v.Group + 1
			case "route-extra":
				routes[0]["nhid"] = 123
			case "missing-route":
				routes = routes[1:]
			case "missing-peer":
				fields["peers"] = ""
			case "link-down":
				link["flags"] = []string{}
			case "port-collision":
				listeners += "\nexternal 51820"
			}
			mutations := 0
			k := deploymentKernel{kernel{run: func(_ context.Context, input, name string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch joined {
				case "-j -N -d link show":
					return json.Marshal([]object{link})
				case "-j -N -4 route show table all":
					return json.Marshal(routes)
				case "-j -N -4 rule show":
					return []byte(`[]`), nil
				case "show all fwmark":
					return []byte(v.Interface + " 0"), nil
				case "show all listen-port":
					return []byte(listeners), nil
				case "-j -N -6 route show table all":
					return json.Marshal(v6)
				case "-j address show dev " + v.Interface:
					return json.Marshal([]object{{"addr_info": addresses}})
				}
				if name == "wg" && len(args) == 3 && args[0] == "show" && args[1] == v.Interface {
					return []byte(fields[args[2]]), nil
				}
				mutations++
				return nil, errors.New("unexpected mutation")
			}}}
			ready, err := k.Check(context.Background(), v, false)
			good := mode == "clean" || mode == "kernel-multicast"
			incomplete := mode == "missing-route" || mode == "missing-peer" || mode == "link-down"
			if ready != good || (err == nil) != (good || incomplete) {
				t.Fatal(mode, ready, err)
			}
			if !good && !incomplete {
				if err := k.Down(context.Background(), v); err == nil {
					t.Fatal("foreign state quiesced")
				}
				if err := k.Remove(context.Background(), v); err == nil {
					t.Fatal("foreign state removed")
				}
			}
			if mutations != 0 || err != nil && strings.Contains(err.Error(), "must-not-disclose") {
				t.Fatal("mutation or secret disclosure", mutations, err)
			}
		})
	}
}
