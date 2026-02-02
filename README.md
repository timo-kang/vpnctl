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
Configuration is YAML. See `configs/example.yaml`. For `vpnctl up/down`, the node config must include:
- `wg_private_key`, `vpn_ip`
- Either `controller` (to fetch server fields) or manual `server_*` fields
- `wg_config_path` (or use `--wg-config`)
Policy routing is enabled by default; override with `policy_routing_enabled: false` if needed.
Direct keepalive tuning can be set with `direct_keepalive_*` fields on nodes.
If `vpn_ip` is omitted, the controller can allocate it from `controller.vpn_cidr`.
When using `node join`, `node run`, or `up` with a config path, the assigned `vpn_ip` is written back into the YAML.

## High-level architecture
- Controller (server): node registry, peer distribution, metrics ingest.
- Agent (node): registers, configures WireGuard, runs tests, reports metrics.
- CLI: operator entrypoint for both controller and node actions.

## Example usage (planned)
```bash
# On server
vpnctl controller init --config configs/example.yaml

# On node
vpnctl node join --config configs/example.yaml
vpnctl node run --config configs/example.yaml
vpnctl node sync-config --config configs/example.yaml

# Discovery + metrics
vpnctl discover
vpnctl ping --all
vpnctl perf --peer modem-b --count 200 --size 1200
vpnctl export csv --out metrics.csv
vpnctl up --config configs/example.yaml
vpnctl down --config configs/example.yaml
vpnctl status --config configs/example.yaml
```

## Direct probe (best-effort)
```bash
# On each node
vpnctl direct serve --config configs/example.yaml

# From another node
vpnctl direct test --config configs/example.yaml --peer modem-b
```

## Direct path (best-effort)
- Nodes run STUN to learn public endpoints.
- Controller exchanges candidates.
- Nodes attempt direct UDP handshake.
- If direct fails, traffic uses server relay.

## Data plane note
WireGuard is used for the tunnel; vpnctl is a control-plane + testing harness.
