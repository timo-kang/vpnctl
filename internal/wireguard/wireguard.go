package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"vpnctl/internal/config"
)

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

// WriteConfig writes WireGuard config to a file with 0600 permissions.
func WriteConfig(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// Up brings up the WireGuard interface using wg-quick.
func Up(configPath string) error {
	cmd := exec.Command("wg-quick", "up", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Down brings down the WireGuard interface using wg-quick.
func Down(configPath string) error {
	cmd := exec.Command("wg-quick", "down", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
