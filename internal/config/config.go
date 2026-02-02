package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	DefaultMTU                   = 1280
	DefaultWGInterface           = "wg0"
	DefaultWGPort                = 51820
	DefaultKeepaliveSec          = 25
	DefaultDirectMode            = "auto"
	DefaultMetricsWindow         = "5m"
	DefaultKeepaliveIntervalSec  = 30
	DefaultSTUNIntervalSec       = 60
	DefaultCandidatesIntervalSec = 30
	DefaultDirectIntervalSec     = 60
	DefaultPolicyRoutingTable    = 51820
	DefaultPolicyRoutingPriority = 1000
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
	DirectMode         string   `yaml:"direct_mode"`
	KeepaliveSec       int      `yaml:"keepalive_sec"`
	STUNServers        []string `yaml:"stun_servers"`
	MetricsPath        string   `yaml:"metrics_path"`
	ServerPublicKey    string   `yaml:"server_public_key"`
	ServerEndpoint     string   `yaml:"server_endpoint"`
	ServerAllowedIPs   []string `yaml:"server_allowed_ips"`
	ServerKeepaliveSec int      `yaml:"server_keepalive_sec"`
	VPNCIDR            string   `yaml:"vpn_cidr"`
}

// NodeConfig is used by the agent process running on a device.
type NodeConfig struct {
	Name                  string   `yaml:"name"`
	Controller            string   `yaml:"controller"`
	WGInterface           string   `yaml:"wg_interface"`
	WGConfigPath          string   `yaml:"wg_config_path"`
	WGPrivateKey          string   `yaml:"wg_private_key"`
	WGPublicKey           string   `yaml:"wg_public_key"`
	WGListenPort          int      `yaml:"wg_listen_port"`
	VPNIP                 string   `yaml:"vpn_ip"`
	MTU                   int      `yaml:"mtu"`
	DirectMode            string   `yaml:"direct_mode"`
	KeepaliveSec          int      `yaml:"keepalive_sec"`
	STUNServers           []string `yaml:"stun_servers"`
	MetricsPath           string   `yaml:"metrics_path"`
	ServerPublicKey       string   `yaml:"server_public_key"`
	ServerEndpoint        string   `yaml:"server_endpoint"`
	ServerAllowedIPs      []string `yaml:"server_allowed_ips"`
	ServerKeepaliveSec    int      `yaml:"server_keepalive_sec"`
	PolicyRoutingEnabled  bool     `yaml:"policy_routing_enabled"`
	PolicyRoutingTable    int      `yaml:"policy_routing_table"`
	PolicyRoutingPriority int      `yaml:"policy_routing_priority"`
	KeepaliveIntervalSec  int      `yaml:"keepalive_interval_sec"`
	STUNIntervalSec       int      `yaml:"stun_interval_sec"`
	CandidatesIntervalSec int      `yaml:"candidates_interval_sec"`
	DirectIntervalSec     int      `yaml:"direct_interval_sec"`
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

	return os.WriteFile(path, data, 0o600)
}

// Validate performs minimal validation for required fields.
func Validate(cfg Config) error {
	if cfg.Controller == nil && cfg.Node == nil {
		return fmt.Errorf("config must contain controller or node section")
	}
	if cfg.Controller != nil && cfg.Controller.Listen == "" {
		return fmt.Errorf("controller.listen is required")
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
	}

	if cfg.Node != nil {
		if cfg.Node.WGInterface == "" {
			cfg.Node.WGInterface = DefaultWGInterface
		}
		if cfg.Node.WGConfigPath == "" {
			cfg.Node.WGConfigPath = fmt.Sprintf("/etc/wireguard/%s.conf", cfg.Node.WGInterface)
		}
		if cfg.Node.PolicyRoutingTable == 0 {
			cfg.Node.PolicyRoutingTable = DefaultPolicyRoutingTable
		}
		if cfg.Node.PolicyRoutingPriority == 0 {
			cfg.Node.PolicyRoutingPriority = DefaultPolicyRoutingPriority
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
	}
}
