// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplink

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"vpnctl/internal/modemsignal"
)

func TestModemSignalsOptInCollection(t *testing.T) {
	runner := commandFake{values: map[string]string{
		"mmcli --list-modems --output-keyvalue": "modem-list.length : 1\nmodem-list.value[1] : /org/freedesktop/ModemManager1/Modem/0",
		"mmcli --modem 0 --output-keyvalue":     "modem.generic.state : connected",
	}}
	calls := 0
	c := LinuxCollector{Runner: runner, Signals: modemsignal.Collector{Read: func(context.Context, string) (string, error) {
		calls++
		return "modem.signal.lte.snr : 0.00\nmodem.3gpp.imei : PRIVATE", nil
	}}}
	cfg := LinkConfig{ID: "cell", Interface: "missing0123", Kind: "lte", Modem: "0"}
	off := c.Collect(context.Background(), cfg)
	if calls != 0 || off.ModemSignals != nil {
		t.Fatal("RF read enabled without opt-in")
	}
	data, _ := json.Marshal(off)
	if strings.Contains(string(data), "modem_signals") {
		t.Fatal("legacy wire changed")
	}
	cfg.ModemSignals = true
	on := c.Collect(context.Background(), cfg)
	if calls != 1 || on.ModemSignals == nil || on.ModemSignals.LTE.SNR.Value == nil || *on.ModemSignals.LTE.SNR.Value != 0 {
		t.Fatal("missing RF data", on)
	}
	if !reflect.DeepEqual(off.Check, on.Check) || !reflect.DeepEqual(off.Modem, on.Modem) {
		t.Fatal("RF changed link/service status")
	}
	data, _ = json.Marshal(on)
	if strings.Contains(string(data), "PRIVATE") {
		t.Fatal("private modem metadata exported")
	}
	runner.values["mmcli --list-modems --output-keyvalue"] = "modem-list.length : 0"
	absent := c.Collect(context.Background(), cfg)
	if calls != 1 || absent.ModemSignals.Reason != "no_modem" || absent.ModemSignals.LTE.SNR.Value != nil {
		t.Fatal("absent modem read/fabricated", absent)
	}
	c.Runner = commandFake{}
	unknown := c.Collect(context.Background(), cfg)
	if calls != 1 || unknown.ModemSignals.State != "unknown" {
		t.Fatal("unverified modem read as present")
	}
}

func TestModemSignalsConfigAndPayloadBoundary(t *testing.T) {
	for _, link := range []LinkConfig{{ID: "cell", Interface: "wwan0", Kind: "wifi", ModemSignals: true}, {ID: "cell", Interface: "wwan0", Kind: "lte", ModemSignals: true}, {ID: "cell", Interface: "wwan0", Kind: "lte", Modem: "00", ModemSignals: true}} {
		cfg := fixtureConfig()
		cfg.Links = []LinkConfig{link}
		if cfg.Validate() == nil {
			t.Fatal("invalid RF configuration accepted", link)
		}
	}
	cfg := fixtureConfig()
	cfg.Links[0] = LinkConfig{ID: "cell", Interface: "missing0123", Kind: "lte", Modem: "0", ModemSignals: true}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c := LinuxCollector{Runner: commandFake{values: map[string]string{"mmcli --list-modems --output-keyvalue": "modem-list.length : 0"}}}
	p := fakeProber{}
	for _, host := range []string{"relay", "target", "control"} {
		p[host] = probeResult{Route{Check: Up(), Interface: "wg0"}, Check{State: "up", RTTMs: ptr(1.0)}}
	}
	s := (Observer{cfg, c, p}).Collect(context.Background())
	if err := s.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	read := modemsignal.Parse("modem.signal.lte.snr : 0", s.At.Add(-time.Second))
	s.Links[0].ModemSignals = &read
	fresh := s.Fresh(s.At)
	if fresh.Stale || fresh.Links[0].ModemSignals.ReadStale {
		t.Fatal("fresh read expired")
	}
	*fresh.Links[0].ModemSignals.LTE.SNR.Value = 9
	if *s.Links[0].ModemSignals.LTE.SNR.Value != 0 {
		t.Fatal("query mutated source")
	}
	aged := s.Fresh(read.ReadAt.Add(180 * time.Second))
	if aged.Stale || !aged.Links[0].ModemSignals.ReadStale {
		t.Fatal("read age hidden by later cycle", aged)
	}
	read.ReadAt = s.At.Add(time.Nanosecond)
	if s.Validate(read.ReadAt) == nil {
		t.Fatal("RF read after cycle accepted")
	}
	read.ReadAt = s.At
	s.Links[0].Kind = "wifi"
	if s.Validate(s.At) == nil {
		t.Fatal("RF attached to unrelated kind")
	}
}

func TestMaximumModemSignalPayloadFitsSnapshotBudget(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Microsecond)
	signal := modemsignal.Parse("modem.signal.lte.rssi : -99.99\nmodem.signal.lte.rsrp : -120.00\nmodem.signal.lte.rsrq : -15.00\nmodem.signal.lte.snr : -1.50\nmodem.signal.5g.rssi : -99.99\nmodem.signal.5g.rsrp : -120.00\nmodem.signal.5g.rsrq : -15.00\nmodem.signal.5g.snr : -1.50", at)
	s := Snapshot{ID: "maximum", At: at, IntervalSec: 60, Underlay: Up()}
	for i := 0; i < MaxLinks; i++ {
		l := Link{ID: strings.Repeat(string(rune('a'+i)), 64), Interface: "wwan" + string(rune('0'+i)), Kind: "lte", Check: Up(), Modem: Up(), ModemSignals: &signal, GatewayState: Up(), DNS: Up(), Controller: Up(), ControllerRoute: Route{Check: Up()}}
		for j := 0; j < 16; j++ {
			l.Addresses = append(l.Addresses, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
			l.Gateways = append(l.Gateways, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		}
		s.Links = append(s.Links, l)
	}
	for i := 0; i < MaxTargets; i++ {
		s.Targets = append(s.Targets, Target{ID: strings.Repeat(string(rune('a'+i)), 64), Protocol: "tcp", Route: Route{Check: Up()}, TransportRoute: Route{Check: Up()}, Relay: Up(), Service: Check{State: "up", RTTMs: ptr(1.0)}, FailureStage: "none", ServiceStartedAt: &at, ServiceCompletedAt: &at})
	}
	if err := s.Validate(at); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxSnapshotBytes {
		t.Fatal("maximum configured RF population exceeds snapshot budget", len(raw), err)
	}
}
