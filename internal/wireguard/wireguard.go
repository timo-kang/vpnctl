package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
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
	return DefaultManager().Up(cfg, setConf)
}

// Down removes the WireGuard interface.
func Down(cfg config.NodeConfig) error {
	return DefaultManager().Down(cfg)
}

// Status returns a basic interface + wg status output.
func Status(iface string) (string, error) {
	return DefaultManager().Status(iface)
}

// ApplyPeers updates WireGuard peers and policy routes for direct paths.
func ApplyPeers(cfg config.NodeConfig, peers []Peer) error {
	return DefaultManager().ApplyPeers(cfg, peers)
}
