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

## High-level architecture
- Controller (server): node registry, peer distribution, metrics ingest.
- Agent (node): registers, configures WireGuard, runs tests, reports metrics.
- CLI: operator entrypoint for both controller and node actions.

## Example usage (planned)
```bash
# On server
vpnctl controller init --listen 0.0.0.0:8443

# On node
vpnctl node join --controller 10.10.10.1:8443 --name modem-a --direct auto
vpnctl up

# Discovery + metrics
vpnctl discover
vpnctl ping --all
vpnctl perf --duration 10s
vpnctl export csv --out metrics.csv
```

## Direct path (best-effort)
- Nodes run STUN to learn public endpoints.
- Controller exchanges candidates.
- Nodes attempt direct UDP handshake.
- If direct fails, traffic uses server relay.

## Data plane note
WireGuard is used for the tunnel; vpnctl is a control-plane + testing harness.

