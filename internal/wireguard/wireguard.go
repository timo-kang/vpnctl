package wireguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"vpnctl/internal/config"
)

// Peer represents a WireGuard peer entry.
type Peer struct {
	PublicKey    string
	Endpoint     string
	AllowedIPs   []string
	KeepaliveSec int
}

// RenderNode renders a WireGuard config for a node using hub-only topology.
func RenderNode(cfg config.NodeConfig) (string, error) {
	if cfg.WGPrivateKey == "" {
		return "", fmt.Errorf("wg_private_key is required")
	}
	if cfg.VPNIP == "" {
		return "", fmt.Errorf("vpn_ip is required")
	}
	if cfg.ServerPublicKey == "" {
		return "", fmt.Errorf("server_public_key is required")
	}
	if cfg.ServerEndpoint == "" {
		return "", fmt.Errorf("server_endpoint is required")
	}
	if len(cfg.ServerAllowedIPs) == 0 {
		return "", fmt.Errorf("server_allowed_ips is required")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(cfg.WGPrivateKey)
	b.WriteString("\n")
	b.WriteString("Address = ")
	b.WriteString(cfg.VPNIP)
	b.WriteString("\n")
	if cfg.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", cfg.MTU)
	}
	if cfg.WGListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.WGListenPort)
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(cfg.ServerPublicKey)
	b.WriteString("\n")
	b.WriteString("Endpoint = ")
	b.WriteString(cfg.ServerEndpoint)
	b.WriteString("\n")
	b.WriteString("AllowedIPs = ")
	b.WriteString(strings.Join(cfg.ServerAllowedIPs, ", "))
	b.WriteString("\n")
	if cfg.ServerKeepaliveSec > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", cfg.ServerKeepaliveSec)
	}

	return b.String(), nil
}

// RenderSetConf renders a wg setconf-compatible config (no Address/MTU).
func RenderSetConf(cfg config.NodeConfig, peers []Peer) (string, error) {
	if cfg.WGPrivateKey == "" {
		return "", fmt.Errorf("wg_private_key is required")
	}
	if cfg.ServerPublicKey == "" {
		return "", fmt.Errorf("server_public_key is required")
	}
	if cfg.ServerEndpoint == "" {
		return "", fmt.Errorf("server_endpoint is required")
	}
	if len(cfg.ServerAllowedIPs) == 0 {
		return "", fmt.Errorf("server_allowed_ips is required")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(cfg.WGPrivateKey)
	b.WriteString("\n")
	if cfg.WGListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.WGListenPort)
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = ")
	b.WriteString(cfg.ServerPublicKey)
	b.WriteString("\n")
	b.WriteString("Endpoint = ")
	b.WriteString(cfg.ServerEndpoint)
	b.WriteString("\n")
	b.WriteString("AllowedIPs = ")
	b.WriteString(strings.Join(cfg.ServerAllowedIPs, ", "))
	b.WriteString("\n")
	if cfg.ServerKeepaliveSec > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", cfg.ServerKeepaliveSec)
	}

	for _, peer := range peers {
		if peer.PublicKey == "" || peer.Endpoint == "" || len(peer.AllowedIPs) == 0 {
			continue
		}
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = ")
		b.WriteString(peer.PublicKey)
		b.WriteString("\n")
		b.WriteString("Endpoint = ")
		b.WriteString(peer.Endpoint)
		b.WriteString("\n")
		b.WriteString("AllowedIPs = ")
		b.WriteString(strings.Join(peer.AllowedIPs, ", "))
		b.WriteString("\n")
		if peer.KeepaliveSec > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.KeepaliveSec)
		}
	}

	return b.String(), nil
}

// WriteConfig writes WireGuard config to a file with 0600 permissions.
func WriteConfig(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// Up brings up the WireGuard interface using ip + wg syncconf.
func Up(cfg config.NodeConfig, setConf string) error {
	if cfg.WGInterface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	if cfg.VPNIP == "" {
		return fmt.Errorf("vpn_ip is required")
	}
	if err := ensureInterface(cfg.WGInterface); err != nil {
		return err
	}
	if err := run("ip", "address", "replace", cfg.VPNIP, "dev", cfg.WGInterface); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := run("ip", "link", "set", "dev", cfg.WGInterface, "mtu", fmt.Sprintf("%d", cfg.MTU)); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", "dev", cfg.WGInterface, "up"); err != nil {
		return err
	}

	if err := syncConf(cfg.WGInterface, setConf); err != nil {
		return err
	}
	for _, cidr := range cfg.ServerAllowedIPs {
		if err := run("ip", "route", "replace", cidr, "dev", cfg.WGInterface); err != nil {
			return err
		}
	}
	if config.PolicyRoutingEnabled(&cfg) {
		if err := ensurePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable); err != nil {
			return err
		}
	}
	return nil
}

// Down removes the WireGuard interface.
func Down(cfg config.NodeConfig) error {
	if config.PolicyRoutingEnabled(&cfg) {
		_ = flushPolicyTable(cfg.PolicyRoutingTable)
		_ = deletePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable)
	}
	if cfg.WGInterface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	return run("ip", "link", "del", "dev", cfg.WGInterface)
}

// Status returns a basic interface + wg status output.
func Status(iface string) (string, error) {
	if iface == "" {
		return "", fmt.Errorf("wg_interface is required")
	}
	ipOut, ipErr := output("ip", "-brief", "addr", "show", "dev", iface)
	wgOut, wgErr := output("wg", "show", iface)
	if ipErr != nil && wgErr != nil {
		return "", fmt.Errorf("ip: %v; wg: %v", ipErr, wgErr)
	}
	var b strings.Builder
	if ipOut != "" {
		b.WriteString("ip:\n")
		b.WriteString(ipOut)
	}
	if wgOut != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("wg:\n")
		b.WriteString(wgOut)
	}
	return b.String(), nil
}

// ApplyPeers updates WireGuard peers and policy routes for direct paths.
func ApplyPeers(cfg config.NodeConfig, peers []Peer) error {
	setConf, err := RenderSetConf(cfg, peers)
	if err != nil {
		return err
	}
	if err := syncConf(cfg.WGInterface, setConf); err != nil {
		return err
	}
	if config.PolicyRoutingEnabled(&cfg) {
		if err := ensurePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable); err != nil {
			return err
		}
		if err := flushPolicyTable(cfg.PolicyRoutingTable); err != nil {
			return err
		}
		for _, peer := range peers {
			for _, cidr := range peer.AllowedIPs {
				if err := run("ip", "route", "replace", cidr, "dev", cfg.WGInterface, "table", strconv.Itoa(cfg.PolicyRoutingTable)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func ensureInterface(iface string) error {
	err := run("ip", "link", "add", "dev", iface, "type", "wireguard")
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func syncConf(iface string, content string) error {
	tmp, err := os.CreateTemp("", "vpnctl-wg-*.conf")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return run("wg", "syncconf", iface, tmp.Name())
}

func ensurePolicyRule(priority int, table int) error {
	if priority <= 0 || table <= 0 {
		return fmt.Errorf("invalid policy routing settings")
	}
	err := run("ip", "rule", "add", "pref", strconv.Itoa(priority), "lookup", strconv.Itoa(table))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func deletePolicyRule(priority int, table int) error {
	if priority <= 0 || table <= 0 {
		return nil
	}
	err := run("ip", "rule", "del", "pref", strconv.Itoa(priority), "lookup", strconv.Itoa(table))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "No such file") {
		return nil
	}
	return err
}

func flushPolicyTable(table int) error {
	if table <= 0 {
		return nil
	}
	return run("ip", "route", "flush", "table", strconv.Itoa(table))
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func output(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err != nil {
		return "", errors.New(buf.String())
	}
	return strings.TrimSpace(buf.String()), nil
}
