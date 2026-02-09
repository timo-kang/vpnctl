package store

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Registry persists registered nodes and their metadata.
type Registry struct {
	UpdatedAt time.Time  `yaml:"updated_at"`
	Nodes     []NodeInfo `yaml:"nodes"`
}

// NodeInfo is a minimal snapshot for controller persistence.
type NodeInfo struct {
	ID         string    `yaml:"id"`
	Name       string    `yaml:"name"`
	PubKey     string    `yaml:"pub_key"`
	VPNIP      string    `yaml:"vpn_ip"`
	Endpoint   string    `yaml:"endpoint"`
	ProbePort  int       `yaml:"probe_port"`
	LastSeenAt time.Time `yaml:"last_seen_at"`
	Status     string    `yaml:"status"`
	NATType    string    `yaml:"nat_type"`
	PublicAddr string    `yaml:"public_addr"`
}

// LoadRegistry loads the registry from disk. If the file is missing, returns an empty registry.
func LoadRegistry(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{}, nil
		}
		return nil, err
	}

	var reg Registry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, err
	}

	return &reg, nil
}

// SaveRegistry writes the registry to disk.
func SaveRegistry(path string, reg *Registry) error {
	if reg == nil {
		return nil
	}
	reg.UpdatedAt = time.Now().UTC()
	data, err := yaml.Marshal(reg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	// Registry contains public keys and network metadata; keep it owner-readable by default.
	return atomicWriteFile(path, data, 0o600)
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
