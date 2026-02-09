# vpnctl

Minimal VPN control-plane + metrics agent for cellular test fleets.

## Goals (MVP)
- Encrypted data plane using WireGuard.
- Hub-and-spoke topology (server relay) with optional direct path when possible.
- Discovery + metrics (latency, jitter, loss, throughput) with CSV export.
- Linux-only nodes.

## Topology
- Default: all traffic goes through the server (public IP).
- Optional: direct node-to-node path if NAT allows it, otherwise relay fallback.

## MTU
- Start at MTU=1280 for cellular reliability.
- Raise later (1380/1420) after path-MTU testing.

## Config
Configuration is YAML. See `configs/example.yaml`.

Node requirements for `vpnctl up/down`:
- `wg_private_key`, `vpn_ip` (or `controller.vpn_cidr` allocation)
- Either `controller` (to fetch server fields) or manual `server_*` fields
- `wg_config_path` (or use `--wg-config`)

Routing defaults:
- Policy routing is enabled by default; set `policy_routing_enabled: false` to disable.
- `policy_routing_cidr` scopes the rule (default: first non-0/0 in `server_allowed_ips`).
- `server_allowed_ips` should usually be the VPN subnet (e.g. `10.7.0.0/24`) to avoid full-tunnel routing.

Direct/relay probing:
- `probe_port` (default `51900`) is used for relay path probes over the VPN.
- `direct_keepalive_*` controls per-peer keepalive tuning for NAT stability.

Controller features:
- If `vpn_ip` is omitted, the controller can allocate it from `controller.vpn_cidr`.
- `controller.wg_apply: true` + `wg_private_key` + `wg_address` lets the controller auto-apply its `wg0` peers (requires root and `wg/ip`).
- When using `node join`, `node run`, or `up` with a config path, the assigned `vpn_ip` is written back into the YAML.

## High-level architecture
- Controller (server): node registry, peer distribution, metrics ingest.
- Agent (node): registers, configures WireGuard, runs tests, reports metrics.
- CLI: operator entrypoint for both controller and node actions.

## Example usage
```bash
# On server
vpnctl controller init --config configs/example.yaml
vpnctl controller status --config configs/example.yaml

# On node
vpnctl node join --config configs/example.yaml
vpnctl node serve --config configs/example.yaml
vpnctl node run --config configs/example.yaml
vpnctl node sync-config --config configs/example.yaml

# Discovery + metrics
vpnctl discover
vpnctl ping --all
vpnctl ping --all --path relay
vpnctl perf --peer modem-b --count 200 --size 1200 --path direct
vpnctl export csv --out metrics.csv
vpnctl up --config configs/example.yaml
vpnctl down --config configs/example.yaml
vpnctl status --config configs/example.yaml
vpnctl doctor --config configs/example.yaml
```

## Direct probe (best-effort)
```bash
# On each node
vpnctl direct serve --config configs/example.yaml

# From another node
vpnctl direct test --config configs/example.yaml --peer modem-b
```

## Direct path (best-effort)
- For VPN traffic, direct node-to-node requires injecting a WireGuard peer entry for the other node.
- The controller can publish each node's WireGuard endpoint as observed on the controller's `wg0` (via `wg show wg0 dump`).
- Nodes can then inject `/32` peers pointing at those observed endpoints.
- STUN is still used for the probe socket and NAT classification; it must not be used as a WireGuard endpoint (different socket, different NAT mapping).

## Routing behavior
- Hub peer keeps `AllowedIPs` for the full VPN subnet (e.g. `/24`).
- Direct peers are injected with `/32` routes on success.
- Most-specific route wins, so direct paths override hub for that peer.

## Data plane note
WireGuard is used for the tunnel; vpnctl is a control-plane + testing harness.
