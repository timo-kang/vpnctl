# vpnctl

Network intelligence for WireGuard. Monitor, diagnose, and analyze any WireGuard network.

Works standalone or alongside Tailscale, Nebula, or plain WireGuard.

## What it does

- **Monitor mode** — real-time TUI dashboard or text output showing peer RTT, loss, and handshake status for any WireGuard interface
- **Fleet status** — fleet-wide view from the controller, or local view from monitor data
- **Diagnostics** — `ping`, `perf`, `doctor`, `discover` work with any WireGuard interface via `--interface`
- **VPN management** — built-in WireGuard mesh with hub-and-spoke relay, optional P2P direct paths, NAT traversal, and tunnel health watchdog

## Quick start

### Monitor any WireGuard interface

```bash
# Real-time TUI dashboard
vpnctl monitor --interface wg0

# Plain text output (for scripts/logging)
vpnctl monitor --interface wg0 --watch

# Filter specific peers
vpnctl monitor --interface wg0 --peers 10.7.0.2,10.7.0.3

# Diagnostics without a vpnctl config
vpnctl ping --interface wg0 --peer 10.7.0.2
vpnctl doctor --interface wg0
vpnctl discover --interface wg0
```

### Fleet overview

```bash
# From controller (full fleet view)
vpnctl fleet status --config controller.yaml
vpnctl fleet history --config controller.yaml --window 24h

# From local monitor data (no controller needed)
vpnctl fleet status --interface wg0
vpnctl fleet history --interface wg0 --window 1h
```

### Full VPN management

```bash
# On server
vpnctl controller init --config configs/controller.yaml

# On node
vpnctl node join --config configs/node.yaml
vpnctl node serve --config configs/node.yaml

# Interface management
vpnctl up --config configs/node.yaml
vpnctl down --config configs/node.yaml
vpnctl status --config configs/node.yaml
vpnctl doctor --config configs/node.yaml
```

## Architecture

```
                    ┌─────────────────────────┐
                    │  Controller / Relay Hub  │
                    │  - Node registry        │
                    │  - Peer distribution    │
                    │  - P2P readiness gate   │
                    │  - Fleet API            │
                    │  - WireGuard relay      │
                    └────────┬────────────────┘
                             │ WireGuard tunnels
                ┌────────────┼────────────────┐
                │            │                │
         ┌──────▼─────┐ ┌───▼────────┐ ┌─────▼──────┐
         │  Node A     │ │  Node B     │ │  Node C     │
         │  (agent)    │ │  (agent)    │ │  (agent)    │
         └──────┬──────┘ └───┬────────┘ └─────┬──────┘
                │            │                │
                └── direct P2P (if verified) ─┘
```

- **Controller**: node registry, peer distribution, P2P readiness gating, fleet API, WireGuard relay hub
- **Agent**: registers with controller, configures WireGuard, probes peers, reports metrics, health watchdog
- **Monitor**: observes any WireGuard interface (with or without vpnctl controller)

## Commands

### Monitor & Fleet (works with any WireGuard)

| Command | Description |
|---|---|
| `vpnctl monitor --interface <iface>` | Real-time TUI dashboard |
| `vpnctl monitor --interface <iface> --watch` | Plain text periodic output |
| `vpnctl fleet status` | Fleet-wide or local peer status |
| `vpnctl fleet history` | Connectivity history over time |

### Diagnostics (--config or --interface)

| Command | Description |
|---|---|
| `vpnctl ping` | RTT, jitter, loss measurement |
| `vpnctl perf` | Throughput + loss measurement |
| `vpnctl discover` | List all known peers |
| `vpnctl doctor` | Interface and routing diagnostics |
| `vpnctl stats` | Aggregated metrics summary |
| `vpnctl status` | WireGuard interface status |

### VPN Management (--config)

| Command | Description |
|---|---|
| `vpnctl controller init` | Start controller server |
| `vpnctl controller status` | Show registered nodes |
| `vpnctl node join` | Register node with controller |
| `vpnctl node serve` | Long-running agent with auto-recovery |
| `vpnctl node run` | Single agent cycle |
| `vpnctl up` / `vpnctl down` | Configure/remove WireGuard interface |
| `vpnctl direct serve` / `vpnctl direct test` | Direct path probing |
| `vpnctl export csv` | Export metrics to file |

## Configuration

YAML config file. See `configs/example.yaml`.

### Key settings

| Setting | Default | Description |
|---|---|---|
| `mtu` | 1280 | Payload MTU (cellular-safe default) |
| `probe_port` | 51900 | UDP echo responder port |
| `direct_mode` | auto | `auto` or `off` |
| `policy_routing_enabled` | true | Per-peer /32 route injection |
| `health_check_interval_sec` | 3 | Tunnel health probe interval |
| `health_check_failures` | 3 | Consecutive failures before tunnel death |
| `p2p_ready_mode` | mutual | `mutual` (both directions) or `either` |

### Monitor data

Monitor stores probe history in SQLite at `~/.vpnctl/monitor.db` (configurable via `--data`). Default retention is 7 days.

## How it works

### Monitor mode

1. Reads peers from `wg show <iface> dump`
2. Sends `vpnctl-echo` UDP probes to each peer's probe port
3. Records RTT and success/failure in local SQLite
4. Displays results in TUI or text output

Requires vpnctl echo responder on target peers (`vpnctl monitor`, `vpnctl node serve`, or `vpnctl direct serve`).

### VPN mesh

1. Nodes register with controller, receive VPN IP and peer list
2. STUN probing classifies NAT type per node
3. Nodes probe peers for direct reachability, report to controller
4. Controller verifies bidirectional reachability before allowing P2P injection
5. Policy routing maintains relay as baseline; /32 direct routes override when verified
6. Tunnel health watchdog detects dead tunnels and triggers auto-recovery

## Requirements

- Linux (WireGuard kernel module or wireguard-go)
- `wg` and `ip` commands available
- Go 1.22+ to build

## License

Apache License 2.0. See [LICENSE](LICENSE).
