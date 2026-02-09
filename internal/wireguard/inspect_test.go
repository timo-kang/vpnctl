package wireguard

import "testing"

func TestParseWgDumpEndpoints(t *testing.T) {
	t.Parallel()

	dump := "" +
		"wg0\t(priv)\t(pub)\t51820\toff\n" +
		"puba\t(psk)\t39.1.2.3:12345\t10.7.0.2/32\t0\t0\t0\toff\n" +
		"pubb\t(psk)\t(none)\t10.7.0.3/32\t0\t0\t0\toff\n" +
		"pubc\t(psk)\t[2001:db8::1]:51820\t10.7.0.4/32\t0\t0\t0\toff\n"

	m := ParseWgDumpEndpoints(dump)
	if got := m["puba"]; got != "39.1.2.3:12345" {
		t.Fatalf("puba=%q", got)
	}
	if _, ok := m["pubb"]; ok {
		t.Fatalf("expected pubb to be missing")
	}
	if got := m["pubc"]; got != "[2001:db8::1]:51820" {
		t.Fatalf("pubc=%q", got)
	}
}
