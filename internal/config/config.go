package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	DefaultMTU                         = 1280
	DefaultWGInterface                 = "wg0"
	DefaultWGPort                      = 51820
	DefaultKeepaliveSec                = 25
	DefaultDirectMode                  = "auto"
	DefaultMetricsWindow               = "5m"
	DefaultKeepaliveIntervalSec        = 30
	DefaultSTUNIntervalSec             = 60
	DefaultCandidatesIntervalSec       = 30
	DefaultDirectIntervalSec           = 60
	DefaultPolicyRoutingTable          = 51820
	DefaultPolicyRoutingPriority       = 1000
	DefaultDirectKeepaliveSec          = 25
	DefaultDirectKeepaliveSymmetricSec = 15
	DefaultDirectKeepaliveUnknownSec   = 20
	DefaultProbePort                   = 51900
	DefaultP2PReadyMode                = "mutual" // mutual|either
	DefaultHealthCheckIntervalSec      = 3
	DefaultHealthCheckFailures         = 3
	DefaultHealthCheckTimeoutSec       = 2
)

// Config holds both controller and node settings.
type Config struct {
	Controller *ControllerConfig `yaml:"controller,omitempty"`
	Node       *NodeConfig       `yaml:"node,omitempty"`
}

// ControllerConfig is used by the controller/server process.
type ControllerConfig struct {
	Listen             string   `yaml:"listen"`
	DataDir            string   `yaml:"data_dir"`
	WGInterface        string   `yaml:"wg_interface"`
	WGPort             int      `yaml:"wg_port"`
	MTU                int      `yaml:"mtu"`
	WGAddress          string   `yaml:"wg_address"`
	WGPrivateKey       string   `yaml:"wg_private_key"`
	WGApply            bool     `yaml:"wg_apply"`
	DirectMode         string   `yaml:"direct_mode"`
	KeepaliveSec       int      `yaml:"keepalive_sec"`
	STUNServers        []string `yaml:"stun_servers"`
	MetricsPath        string   `yaml:"metrics_path"`
	ServerPublicKey    string   `yaml:"server_public_key"`
	ServerEndpoint     string   `yaml:"server_endpoint"`
	ServerAllowedIPs   []string `yaml:"server_allowed_ips"`
	ServerKeepaliveSec int      `yaml:"server_keepalive_sec"`
	VPNCIDR            string   `yaml:"vpn_cidr"`
	// P2PReadyMode controls when controller marks a peer-pair safe for /32 direct injection.
	// mutual: requires recent success in both directions (safe, conservative).
	// either: requires recent success in either direction (symmetric injection, more permissive).
	P2PReadyMode string `yaml:"p2p_ready_mode"`
	ProbePort    int    `yaml:"probe_port"`
}

// NodeConfig is used by the agent process running on a device.
type NodeConfig struct {
	Name                        string   `yaml:"name"`
	Controller                  string   `yaml:"controller"`
	WGInterface                 string   `yaml:"wg_interface"`
	WGConfigPath                string   `yaml:"wg_config_path"`
	WGPrivateKey                string   `yaml:"wg_private_key"`
	WGPublicKey                 string   `yaml:"wg_public_key"`
	WGListenPort                int      `yaml:"wg_listen_port"`
	ProbePort                   int      `yaml:"probe_port"`
	VPNIP                       string   `yaml:"vpn_ip"`
	MTU                         int      `yaml:"mtu"`
	DirectMode                  string   `yaml:"direct_mode"`
	KeepaliveSec                int      `yaml:"keepalive_sec"`
	STUNServers                 []string `yaml:"stun_servers"`
	MetricsPath                 string   `yaml:"metrics_path"`
	ServerPublicKey             string   `yaml:"server_public_key"`
	ServerEndpoint              string   `yaml:"server_endpoint"`
	ServerAllowedIPs            []string `yaml:"server_allowed_ips"`
	ServerKeepaliveSec          int      `yaml:"server_keepalive_sec"`
	PolicyRoutingEnabled        *bool    `yaml:"policy_routing_enabled"`
	PolicyRoutingTable          int      `yaml:"policy_routing_table"`
	PolicyRoutingPriority       int      `yaml:"policy_routing_priority"`
	PolicyRoutingCIDR           string   `yaml:"policy_routing_cidr"`
	DirectKeepaliveSec          int      `yaml:"direct_keepalive_sec"`
	DirectKeepaliveSymmetricSec int      `yaml:"direct_keepalive_symmetric_sec"`
	DirectKeepaliveUnknownSec   int      `yaml:"direct_keepalive_unknown_sec"`
	KeepaliveIntervalSec        int      `yaml:"keepalive_interval_sec"`
	STUNIntervalSec             int      `yaml:"stun_interval_sec"`
	CandidatesIntervalSec       int      `yaml:"candidates_interval_sec"`
	DirectIntervalSec           int      `yaml:"direct_interval_sec"`
	// AdvertiseWGEndpoint, when set, is the WireGuard endpoint other peers should dial for direct injection.
	// Use this for port-forwarded nodes (e.g. "WAN_IP:51820"). When unset, controller will publish the
	// endpoint it observes on its own wg0.
	AdvertiseWGEndpoint string `yaml:"advertise_wg_endpoint"`
	// AdvertisePublicAddr, when set, is the direct probe address other peers should use (e.g. "WAN_IP:51900").
	// This is required when you use port-forwarding because STUN on the probe socket returns a random mapped port.
	AdvertisePublicAddr    string `yaml:"advertise_public_addr"`
	HealthCheckIntervalSec int    `yaml:"health_check_interval_sec"`
	HealthCheckFailures    int    `yaml:"health_check_failures"`
	HealthCheckTimeoutSec  int    `yaml:"health_check_timeout_sec"`
}

// Load reads and parses a YAML config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	ApplyDefaults(&cfg)
	return cfg, nil
}

// Save writes a YAML config file to disk.
func Save(path string, cfg Config) error {
	ApplyDefaults(&cfg)
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return atomicWriteFile(path, data, 0o600)
}

// Validate performs minimal validation for required fields.
func Validate(cfg Config) error {
	if cfg.Controller == nil && cfg.Node == nil {
		return fmt.Errorf("config must contain controller or node section")
	}
	if cfg.Controller != nil && cfg.Controller.Listen == "" {
		return fmt.Errorf("controller.listen is required")
	}
	if cfg.Controller != nil && cfg.Controller.WGApply {
		if cfg.Controller.WGPrivateKey == "" {
			return fmt.Errorf("controller.wg_private_key is required when wg_apply is true")
		}
		if cfg.Controller.WGAddress == "" {
			return fmt.Errorf("controller.wg_address is required when wg_apply is true")
		}
	}
	if cfg.Node != nil && cfg.Node.Name == "" {
		return fmt.Errorf("node.name is required")
	}
	if cfg.Node != nil {
		if cfg.Node.Controller == "" && (cfg.Node.ServerPublicKey == "" || cfg.Node.ServerEndpoint == "" || len(cfg.Node.ServerAllowedIPs) == 0) {
			return fmt.Errorf("node.controller is required unless server fields are set")
		}
	}
	return nil
}

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

// ApplyDefaults fills in default values when empty.
func ApplyDefaults(cfg *Config) {
	if cfg.Controller != nil {
		if cfg.Controller.WGInterface == "" {
			cfg.Controller.WGInterface = DefaultWGInterface
		}
		if cfg.Controller.WGPort == 0 {
			cfg.Controller.WGPort = DefaultWGPort
		}
		if cfg.Controller.MTU == 0 {
			cfg.Controller.MTU = DefaultMTU
		}
		if cfg.Controller.DirectMode == "" {
			cfg.Controller.DirectMode = DefaultDirectMode
		}
		if cfg.Controller.KeepaliveSec == 0 {
			cfg.Controller.KeepaliveSec = DefaultKeepaliveSec
		}
		if cfg.Controller.P2PReadyMode == "" {
			cfg.Controller.P2PReadyMode = DefaultP2PReadyMode
		}
		if cfg.Controller.ProbePort == 0 {
			cfg.Controller.ProbePort = DefaultProbePort
		}
	}

	if cfg.Node != nil {
		if cfg.Node.WGInterface == "" {
			cfg.Node.WGInterface = DefaultWGInterface
		}
		if cfg.Node.WGConfigPath == "" {
			cfg.Node.WGConfigPath = fmt.Sprintf("/etc/wireguard/%s.conf", cfg.Node.WGInterface)
		}
		if cfg.Node.ProbePort == 0 {
			cfg.Node.ProbePort = DefaultProbePort
		}
		if cfg.Node.PolicyRoutingEnabled == nil {
			enabled := true
			cfg.Node.PolicyRoutingEnabled = &enabled
		}
		if cfg.Node.PolicyRoutingCIDR == "" {
			cfg.Node.PolicyRoutingCIDR = firstScopedCIDR(cfg.Node.ServerAllowedIPs)
		}
		if cfg.Node.PolicyRoutingTable == 0 {
			cfg.Node.PolicyRoutingTable = DefaultPolicyRoutingTable
		}
		if cfg.Node.PolicyRoutingPriority == 0 {
			cfg.Node.PolicyRoutingPriority = DefaultPolicyRoutingPriority
		}
		if cfg.Node.DirectKeepaliveSec == 0 {
			cfg.Node.DirectKeepaliveSec = DefaultDirectKeepaliveSec
		}
		if cfg.Node.DirectKeepaliveSymmetricSec == 0 {
			cfg.Node.DirectKeepaliveSymmetricSec = DefaultDirectKeepaliveSymmetricSec
		}
		if cfg.Node.DirectKeepaliveUnknownSec == 0 {
			cfg.Node.DirectKeepaliveUnknownSec = DefaultDirectKeepaliveUnknownSec
		}
		if cfg.Node.MTU == 0 {
			cfg.Node.MTU = DefaultMTU
		}
		if cfg.Node.DirectMode == "" {
			cfg.Node.DirectMode = DefaultDirectMode
		}
		if cfg.Node.KeepaliveSec == 0 {
			cfg.Node.KeepaliveSec = DefaultKeepaliveSec
		}
		if cfg.Node.KeepaliveIntervalSec == 0 {
			cfg.Node.KeepaliveIntervalSec = DefaultKeepaliveIntervalSec
		}
		if cfg.Node.STUNIntervalSec == 0 {
			cfg.Node.STUNIntervalSec = DefaultSTUNIntervalSec
		}
		if cfg.Node.CandidatesIntervalSec == 0 {
			cfg.Node.CandidatesIntervalSec = DefaultCandidatesIntervalSec
		}
		if cfg.Node.DirectIntervalSec == 0 {
			cfg.Node.DirectIntervalSec = DefaultDirectIntervalSec
		}
		if cfg.Node.HealthCheckIntervalSec == 0 {
			cfg.Node.HealthCheckIntervalSec = DefaultHealthCheckIntervalSec
		}
		if cfg.Node.HealthCheckFailures == 0 {
			cfg.Node.HealthCheckFailures = DefaultHealthCheckFailures
		}
		if cfg.Node.HealthCheckTimeoutSec == 0 {
			cfg.Node.HealthCheckTimeoutSec = DefaultHealthCheckTimeoutSec
		}
	}
}

// PolicyRoutingEnabled returns true when policy routing should be active.
func PolicyRoutingEnabled(cfg *NodeConfig) bool {
	if cfg == nil {
		return false
	}
	if cfg.PolicyRoutingEnabled == nil {
		return true
	}
	return *cfg.PolicyRoutingEnabled
}

func firstScopedCIDR(values []string) string {
	for _, value := range values {
		if value == "" {
			continue
		}
		if value == "0.0.0.0/0" || value == "::/0" {
			continue
		}
		return value
	}
	return ""
}
