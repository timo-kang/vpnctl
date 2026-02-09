package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vpnctl/internal/config"
	"vpnctl/internal/execx"
)

// Manager executes ip/wg commands. It is injectable for unit tests.
type Manager struct {
	r execx.Runner
}

func NewManager(r execx.Runner) *Manager {
	if r == nil {
		r = execx.NewOSRunner(os.Stdout, os.Stderr)
	}
	return &Manager{r: r}
}

var defaultManager = NewManager(execx.NewOSRunner(os.Stdout, os.Stderr))

func DefaultManager() *Manager {
	return defaultManager
}

// Up brings up the WireGuard interface using ip + wg syncconf.
func (m *Manager) Up(cfg config.NodeConfig, setConf string) error {
	if cfg.WGInterface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	if cfg.VPNIP == "" {
		return fmt.Errorf("vpn_ip is required")
	}
	if err := m.ensureInterface(cfg.WGInterface); err != nil {
		return err
	}
	if err := m.run("ip", "address", "replace", cfg.VPNIP, "dev", cfg.WGInterface); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.run("ip", "link", "set", "dev", cfg.WGInterface, "mtu", fmt.Sprintf("%d", cfg.MTU)); err != nil {
			return err
		}
	}
	if err := m.run("ip", "link", "set", "dev", cfg.WGInterface, "up"); err != nil {
		return err
	}

	if err := m.syncConf(cfg.WGInterface, setConf); err != nil {
		return err
	}
	for _, cidr := range cfg.ServerAllowedIPs {
		if err := m.run("ip", "route", "replace", cidr, "dev", cfg.WGInterface); err != nil {
			return err
		}
	}
	if config.PolicyRoutingEnabled(&cfg) {
		if err := m.ensurePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable, cfg.PolicyRoutingCIDR); err != nil {
			return err
		}
	}
	return nil
}

// Down removes the WireGuard interface.
func (m *Manager) Down(cfg config.NodeConfig) error {
	if config.PolicyRoutingEnabled(&cfg) {
		_ = m.flushPolicyTable(cfg.PolicyRoutingTable)
		_ = m.deletePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable, cfg.PolicyRoutingCIDR)
	}
	if cfg.WGInterface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	err := m.run("ip", "link", "del", "dev", cfg.WGInterface)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "Cannot find device") || strings.Contains(err.Error(), "does not exist") {
		return nil
	}
	return err
}

// Status returns a basic interface + wg status output.
func (m *Manager) Status(iface string) (string, error) {
	if iface == "" {
		return "", fmt.Errorf("wg_interface is required")
	}
	ipOut, ipErr := m.output("ip", "-brief", "addr", "show", "dev", iface)
	wgOut, wgErr := m.output("wg", "show", iface)
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
func (m *Manager) ApplyPeers(cfg config.NodeConfig, peers []Peer) error {
	setConf, err := RenderSetConf(cfg, peers)
	if err != nil {
		return err
	}
	if err := m.syncConf(cfg.WGInterface, setConf); err != nil {
		return err
	}
	if config.PolicyRoutingEnabled(&cfg) {
		if err := m.ensurePolicyRule(cfg.PolicyRoutingPriority, cfg.PolicyRoutingTable, cfg.PolicyRoutingCIDR); err != nil {
			return err
		}
		if err := m.flushPolicyTable(cfg.PolicyRoutingTable); err != nil {
			return err
		}
		for _, peer := range peers {
			for _, cidr := range peer.AllowedIPs {
				if err := m.run("ip", "route", "replace", cidr, "dev", cfg.WGInterface, "table", strconv.Itoa(cfg.PolicyRoutingTable)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ApplyServer ensures the interface is up and syncs peers (controller side).
func (m *Manager) ApplyServer(cfg ServerConfig, peers []Peer) error {
	if cfg.Interface == "" {
		return fmt.Errorf("wg_interface is required")
	}
	if cfg.Address == "" {
		return fmt.Errorf("wg_address is required")
	}
	if err := m.ensureInterface(cfg.Interface); err != nil {
		return err
	}
	if err := m.run("ip", "address", "replace", cfg.Address, "dev", cfg.Interface); err != nil {
		return err
	}
	if cfg.MTU > 0 {
		if err := m.run("ip", "link", "set", "dev", cfg.Interface, "mtu", fmt.Sprintf("%d", cfg.MTU)); err != nil {
			return err
		}
	}
	if err := m.run("ip", "link", "set", "dev", cfg.Interface, "up"); err != nil {
		return err
	}

	setConf, err := RenderServerSetConf(cfg, peers)
	if err != nil {
		return err
	}
	return m.syncConf(cfg.Interface, setConf)
}

func (m *Manager) ensureInterface(iface string) error {
	if m.interfaceExists(iface) {
		return nil
	}
	err := m.run("ip", "link", "add", "dev", iface, "type", "wireguard")
	if err == nil {
		return nil
	}
	// Best-effort idempotency (e.g. concurrent `up` runs).
	if strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func (m *Manager) interfaceExists(iface string) bool {
	_, err := m.output("ip", "link", "show", "dev", iface)
	return err == nil
}

func (m *Manager) syncConf(iface string, content string) error {
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
	return m.run("wg", "syncconf", iface, tmp.Name())
}

func (m *Manager) ensurePolicyRule(priority int, table int, cidr string) error {
	if priority <= 0 || table <= 0 {
		return fmt.Errorf("invalid policy routing settings")
	}
	if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
		return fmt.Errorf("policy_routing_cidr is required and must be scoped")
	}
	err := m.run("ip", "rule", "add", "pref", strconv.Itoa(priority), "to", cidr, "lookup", strconv.Itoa(table))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func (m *Manager) deletePolicyRule(priority int, table int, cidr string) error {
	if priority <= 0 || table <= 0 {
		return nil
	}
	args := []string{"rule", "del", "pref", strconv.Itoa(priority), "lookup", strconv.Itoa(table)}
	if cidr != "" {
		args = []string{"rule", "del", "pref", strconv.Itoa(priority), "to", cidr, "lookup", strconv.Itoa(table)}
	}
	err := m.run("ip", args...)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "No such file") {
		return nil
	}
	return err
}

func (m *Manager) flushPolicyTable(table int) error {
	if table <= 0 {
		return nil
	}
	return m.run("ip", "route", "flush", "table", strconv.Itoa(table))
}

func (m *Manager) run(name string, args ...string) error {
	if m == nil || m.r == nil {
		return fmt.Errorf("runner not initialized")
	}
	return m.r.Run(name, args...)
}

func (m *Manager) output(name string, args ...string) (string, error) {
	if m == nil || m.r == nil {
		return "", fmt.Errorf("runner not initialized")
	}
	return m.r.Output(name, args...)
}

// atomicWriteFile is used by probe/export helpers. Not currently exposed, but kept here
// since Manager owns side-effecting operations.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}
