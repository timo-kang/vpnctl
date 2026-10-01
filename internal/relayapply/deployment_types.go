// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayapply

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"vpnctl/internal/relaycache"
	"vpnctl/internal/relaycatalog"
)

type DeploymentOptions struct {
	EndpointID    string
	KeyFile       string
	KeyGeneration uint64
	ListenPort    int
}
type DeploymentPeer struct {
	PathID    string `json:"path_id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}
type DeploymentEntry struct {
	Controller    string           `json:"controller_id"`
	Endpoint      string           `json:"endpoint_id"`
	Interface     string           `json:"interface"`
	PublicKey     string           `json:"public_key"`
	KeyGeneration uint64           `json:"key_generation"`
	ListenPort    int              `json:"listen_port"`
	Peers         []DeploymentPeer `json:"peers"`
	Alias         string           `json:"alias"`
	LinkIndex     uint32           `json:"link_index"`
	Group         uint32           `json:"group"`
	Phase         string           `json:"phase"`
}
type deploymentJournal struct {
	Version   int               `json:"version"`
	Principal string            `json:"principal_id"`
	Relay     string            `json:"relay_id"`
	Domain    string            `json:"kernel_domain"`
	Entries   []DeploymentEntry `json:"entries"`
}
type deploymentEnvelope struct {
	Journal deploymentJournal `json:"journal"`
	Digest  string            `json:"sha256"`
}
type DeploymentResult struct {
	SchemaVersion     int                        `json:"schema_version"`
	State             string                     `json:"state"`
	Reason            string                     `json:"reason,omitempty"`
	RelayID           string                     `json:"relay_id"`
	KernelReady       bool                       `json:"kernel_ready"`
	UplinkHealth      string                     `json:"uplink_health"`
	ExpiryEnforcement string                     `json:"expiry_enforcement"`
	Endpoints         []DeploymentEndpointResult `json:"endpoints"`
}
type DeploymentEndpointResult struct {
	EndpointID  string `json:"endpoint_id"`
	Interface   string `json:"interface"`
	Phase       string `json:"phase"`
	Peers       int    `json:"peers"`
	KernelReady bool   `json:"kernel_ready"`
}

func deploymentHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func deploymentInterface(controller, principal, relay, endpoint string) string {
	return "vd" + deploymentHash([]string{controller, principal, relay, endpoint})[:12]
}
func deploymentKey(file, public string) (string, error) {
	b, err := relaycache.ReadDeploymentKey(file)
	if err != nil {
		return "", err
	}
	s := strings.TrimSuffix(string(b), "\n")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != s {
		return "", errors.New("invalid relay private key encoding")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) != public {
		return "", errors.New("local relay key does not match approval")
	}
	return s, nil
}
func desiredDeployment(r relaycache.DeploymentReport, endpoint string, port int) (DeploymentEntry, error) {
	if !r.ApprovalValid || r.Deployment == nil || r.Deployment.Validate(r.PrincipalID, r.RelayID, time.Now()) != nil {
		return DeploymentEntry{}, errors.New("relay approval unavailable")
	}
	v := r.Deployment
	relay := v.Spec.Relays[0]
	if port < 1 || port > 65535 || !slices.ContainsFunc(relay.Endpoints, func(ep relaycatalog.Endpoint) bool { return ep.ID == endpoint }) {
		return DeploymentEntry{}, errors.New("endpoint or local listen port invalid")
	}
	e := DeploymentEntry{Controller: v.ControllerID, Endpoint: endpoint, Interface: deploymentInterface(v.ControllerID, r.PrincipalID, r.RelayID, endpoint), PublicKey: relay.PublicKey, KeyGeneration: relay.KeyGeneration, ListenPort: port, Peers: []DeploymentPeer{}, Phase: "preparing"}
	paths := map[string]bool{}
	for _, p := range v.Spec.Paths {
		if p.EndpointID == endpoint {
			paths[p.ID] = true
		}
	}
	for _, b := range v.Bindings {
		if paths[b.PathID] {
			e.Peers = append(e.Peers, DeploymentPeer{b.PathID, b.PublicKey, b.InnerAddress})
		}
	}
	slices.SortFunc(e.Peers, func(a, b DeploymentPeer) int { return strings.Compare(a.PublicKey, b.PublicKey) })
	return e, nil
}
func sameDeployment(a, b DeploymentEntry) bool {
	a.Alias, b.Alias = "", ""
	a.LinkIndex, b.LinkIndex = 0, 0
	a.Group, b.Group = 0, 0
	a.Phase, b.Phase = "", ""
	return deploymentHash(a) == deploymentHash(b)
}
func validateDeploymentEntry(e DeploymentEntry, j deploymentJournal) error {
	id, err := hex.DecodeString(e.Controller)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != e.Controller || relaycache.ValidateDeploymentIdentity(j.Principal, e.Endpoint) != nil || e.Interface != deploymentInterface(e.Controller, j.Principal, j.Relay, e.Endpoint) || relaycatalog.ValidatePublicKey(e.PublicKey) != nil || e.KeyGeneration == 0 || e.ListenPort < 1 || e.ListenPort > 65535 || e.Peers == nil || len(e.Peers) > relaycatalog.MaxNodes*relaycatalog.MaxPathsPerNode {
		return errors.New("invalid deployment ownership journal")
	}
	if e.Phase != "preparing" && e.Phase != "applied" && e.Phase != "releasing" {
		return errors.New("invalid deployment phase")
	}
	if len(e.Alias) != 39 || !strings.HasPrefix(e.Alias, "vpnctl:") {
		return errors.New("invalid deployment owner")
	}
	if _, err := hex.DecodeString(e.Alias[7:]); err != nil {
		return errors.New("invalid deployment owner")
	}
	if e.LinkIndex < 100000 || e.LinkIndex > 0x3fffffff+100000 || e.Group < 100000 || e.Group > 0x3fffffff+100000 {
		return errors.New("invalid deployment resource identity")
	}
	seen := map[string]bool{}
	for _, p := range e.Peers {
		ip, err := netip.ParsePrefix(p.Address)
		if relaycache.ValidateDeploymentIdentity(j.Principal, p.PathID) != nil || relaycatalog.ValidatePublicKey(p.PublicKey) != nil || p.PublicKey == e.PublicKey || err != nil || !ip.Addr().Is4() || ip.Bits() != 32 || ip.String() != p.Address || !ip.Addr().IsGlobalUnicast() || seen["ip:"+p.Address] || seen["key:"+p.PublicKey] || seen["path:"+p.PathID] {
			return errors.New("invalid deployment peer journal")
		}
		seen["ip:"+p.Address], seen["key:"+p.PublicKey], seen["path:"+p.PathID] = true, true, true
	}
	return nil
}
