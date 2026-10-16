//go:build integration

// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Ephemeral mutual TLS identity. Keys remain in the fixture's private directory.
func uplinkPKI(t *testing.T, dir string) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	caKey := key()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "comparison-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	write := func(name string, cert *x509.Certificate, parent *x509.Certificate, k, signer *ecdsa.PrivateKey) {
		der, e := x509.CreateCertificate(rand.Reader, cert, parent, &k.PublicKey, signer)
		if e != nil {
			t.Fatal(e)
		}
		b, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		mustWrite(t, filepath.Join(dir, name+".crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
		mustWrite(t, filepath.Join(dir, name+".key"), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})))
	}
	write("ca", ca, ca, caKey, caKey)
	for i, name := range []string{"server", "client"} {
		usage := x509.ExtKeyUsageServerAuth
		if name == "client" {
			usage = x509.ExtKeyUsageClientAuth
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		write(name, c, ca, key(), caKey)
	}
}

func openVPNUplinkFixture(t *testing.T, paths int, robot, server *capacityGroup, resultDir string) *uplinkFixture {
	t.Helper()
	layout := newM3TopologyLayoutWithUnderlays(t, true, paths/2)
	uplinkControlPath(t, layout.robot, layout.controller)
	f := &uplinkFixture{robot: layout.robot, relays: layout.relays, logs: map[string]string{}, roles: map[string]any{}}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	uplinkPKI(t, private)
	worker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run(t, ".", "modprobe", "tun")
	netOutput(t, layout.robot, "sh", "-c", "mount -t proc proc /proc && printf 0 > /proc/sys/net/ipv4/conf/all/rp_filter && printf 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	netOutput(t, layout.target, "ip", "addr", "add", "198.18.0.3/32", "dev", "eth0")
	for _, target := range []string{m3Target, "198.18.0.3"} {
		startNetworkProcess(t, layout.target, filepath.Join(private, "echo-"+target+".log"), []string{"VPNCTL_WORKER=m3-echo", "VPNCTL_PROBE_TARGET=" + target}, worker, "-test.run=^TestNetworkWorker$")
	}
	common := fmt.Sprintf("proto udp4\ndev bench0\ndev-type tun\ntopology subnet\nca %s/ca.crt\ndata-ciphers AES-256-GCM\ntls-version-min 1.2\ndisable-dco\nverb 3\n", private)
	for i, ns := range layout.relays {
		netOutput(t, ns, "nft", "delete", "table", "ip", "m3")
		(relayUplink{relay: ns}).nft(t, fmt.Sprintf(`table ip m3 {
 chain forward { type filter hook forward priority filter; policy drop;
 iifname "bench0" oifname "uplink0" ip daddr {198.18.0.2,198.18.0.3} tcp dport 9192 accept
 iifname "uplink0" oifname "bench0" ct state established,related accept
 }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
 oifname "uplink0" ip saddr 10.89.0.0/24 ip daddr {198.18.0.2,198.18.0.3} tcp dport 9192 snat to 198.18.0.%d
 }
}`, 11+i))
		conf := common + fmt.Sprintf("cert %s/server.crt\nkey %s/server.key\ndh none\nremote-cert-tls client\nport 1194\nmultihome\nserver 10.89.0.0 255.255.255.0\nkeepalive 1 5\n", private, private)
		path := filepath.Join(private, fmt.Sprintf("server%d.conf", i))
		mustWrite(t, path, conf)
		log := filepath.Join(resultDir, fmt.Sprintf("relay%d.log", i))
		f.logs[fmt.Sprintf("relay%d", i)] = log
		p := startNetworkProcess(t, ns, log, nil, "openvpn", "--config", path)
		f.roles[fmt.Sprintf("relay%d", i)] = server.placement(t, p.cmd.Process.Pid)
	}
	conf := common + fmt.Sprintf("client\ncert %s/client.crt\nkey %s/client.key\nremote-cert-tls server\nverify-x509-name server name\nnobind\npersist-key\npersist-tun\nping 1\nping-restart 5\nhand-window 3\nconnect-retry 1 1\nroute 198.18.0.2 255.255.255.255\nroute 198.18.0.3 255.255.255.255\n", private, private)
	for r := 0; r < 2; r++ {
		for u, prefix := range uplinkPrefixes[:paths/2] {
			f.paths = append(f.paths, uplinkPath{ID: fmt.Sprintf("p%d%d", r, u), Relay: r, Underlay: u, Port: 1194})
			conf += fmt.Sprintf("remote %s.%d 1194\n", prefix, 11+r)
		}
	}
	management := filepath.Join(private, "ovpn.sock")
	conf += "management " + management + " unix\n"
	path := filepath.Join(private, "client.conf")
	mustWrite(t, path, conf)
	log := filepath.Join(resultDir, "client.log")
	f.logs["client"] = log
	p := startNetworkProcessInGroup(t, robot.file, layout.robot, log, nil, "openvpn", "--config", path)
	f.roles["client"] = robot.placement(t, p.cmd.Process.Pid)
	f.primary = func() error {
		remote, err := openVPNRemote(management)
		if err != nil {
			return err
		}
		if remote != "192.0.2.11:1194" {
			return fmt.Errorf("primary endpoint changed")
		}
		return nil
	}
	f.selection = func() map[string]string {
		remote, err := openVPNRemote(management)
		id := "not_connected"
		if err == nil {
			for _, p := range f.paths {
				if remote == fmt.Sprintf("%s.%d:%d", uplinkPrefixes[p.Underlay], 11+p.Relay, p.Port) {
					id = p.ID
				}
			}
		}
		return map[string]string{"tunnel": id}
	}
	eventually(t, 30*time.Second, "OpenVPN initial endpoint", f.primary)
	f.endpointPort = 1194
	f.version = strings.Split(netOutput(t, layout.robot, "openvpn", "--version"), "\n")[0]
	// Store public configuration separately without ephemeral key paths.
	f.profile = strings.ReplaceAll(conf, private, "<private>")
	return f
}

// Query current management state, not historical log text. A reconnect to another
// underlay before injection would otherwise make the selected-endpoint fault void.
func openVPNRemote(path string) (string, error) {
	c, e := net.DialTimeout("unix", path, time.Second)
	if e != nil {
		return "", fmt.Errorf("management unavailable")
	}
	defer c.Close()
	if e = c.SetDeadline(time.Now().Add(time.Second)); e != nil {
		return "", e
	}
	if _, e = io.WriteString(c, "state\n"); e != nil {
		return "", e
	}
	scanner := bufio.NewScanner(io.LimitReader(c, 16384))
	scanner.Buffer(make([]byte, 4096), 4096)
	remote := ""
	for scanner.Scan() {
		line := scanner.Text()
		if line == "END" {
			if remote != "" {
				return remote, nil
			}
			return "", fmt.Errorf("not connected")
		}
		fields := strings.Split(line, ",")
		if len(fields) < 6 {
			continue
		}
		if _, e := strconv.ParseInt(fields[0], 10, 64); e != nil {
			continue
		}
		remote = ""
		if fields[1] == "CONNECTED" && fields[2] == "SUCCESS" {
			remote = fields[4] + ":" + fields[5]
		}
	}
	return "", fmt.Errorf("incomplete management state")
}
