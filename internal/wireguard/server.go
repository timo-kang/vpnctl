package wireguard

import (
	"fmt"
	"strings"
)

// ServerConfig holds minimal WireGuard settings for the controller host.
type ServerConfig struct {
	Interface  string
	PrivateKey string
	Address    string
	ListenPort int
	MTU        int
}

// RenderServerSetConf renders wg setconf config for the controller.
func RenderServerSetConf(cfg ServerConfig, peers []Peer) (string, error) {
	if cfg.PrivateKey == "" {
		return "", fmt.Errorf("wg_private_key is required")
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = ")
	b.WriteString(cfg.PrivateKey)
	b.WriteString("\n")
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	}

	for _, peer := range peers {
		if peer.PublicKey == "" || len(peer.AllowedIPs) == 0 {
			continue
		}
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = ")
		b.WriteString(peer.PublicKey)
		b.WriteString("\n")
		b.WriteString("AllowedIPs = ")
		b.WriteString(strings.Join(peer.AllowedIPs, ", "))
		b.WriteString("\n")
		if peer.Endpoint != "" {
			b.WriteString("Endpoint = ")
			b.WriteString(peer.Endpoint)
			b.WriteString("\n")
		}
		if peer.KeepaliveSec > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", peer.KeepaliveSec)
		}
	}

	return b.String(), nil
}

// ApplyServer ensures the interface is up and syncs peers.
func ApplyServer(cfg ServerConfig, peers []Peer) error {
	if cfg.Interface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	if cfg.Address == "" {
		return fmt.Errorf("wg_address is required")
	}
	if err := ensureInterface(cfg.Interface); err != nil {
		return err
	}
	if err := run("ip", "address", "replace", cfg.Address, "dev", cfg.Interface); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := run("ip", "link", "set", "dev", cfg.Interface, "mtu", fmt.Sprintf("%d", cfg.MTU)); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", "dev", cfg.Interface, "up"); err != nil {
		return err
	}

	setConf, err := RenderServerSetConf(cfg, peers)
	if err != nil {
		return err
	}
	return syncConf(cfg.Interface, setConf)
}
