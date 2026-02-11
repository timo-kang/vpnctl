package addrutil

import "testing"

func TestProbeAddr_PublicAddrOverridesPort(t *testing.T) {
	addr, ok := ProbeAddr("39.119.108.243:33134", "39.119.108.243:51820", 51900)
	if !ok {
		t.Fatal("expected ok")
	}
	if addr != "39.119.108.243:51900" {
		t.Fatalf("addr=%q", addr)
	}
}

func TestProbeAddr_EndpointUsedWhenPublicAddrMissing(t *testing.T) {
	addr, ok := ProbeAddr("", "39.119.108.243:51820", 51900)
	if !ok {
		t.Fatal("expected ok")
	}
	if addr != "39.119.108.243:51900" {
		t.Fatalf("addr=%q", addr)
	}
}

func TestProbeAddr_UnbracketedIPv6HostPort(t *testing.T) {
	addr, ok := ProbeAddr("", "2001:db8::1:51820", 51900)
	if !ok {
		t.Fatal("expected ok")
	}
	if addr != "[2001:db8::1]:51900" {
		t.Fatalf("addr=%q", addr)
	}
}

