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

## Authentication (mTLS)

vpnctl supports mutual TLS authentication. When enabled, all API communication between nodes and the controller is encrypted and mutually authenticated.

### Setup

1. Add `pki:` section to controller config:

```yaml
controller:
  listen: "0.0.0.0:8443"
  data_dir: "/var/lib/vpnctl"
  vpn_cidr: "10.7.0.0/24"
  pki:
    ca_expiry: "87600h"      # 10 years
    server_expiry: "8760h"   # 1 year
    client_expiry: "8760h"   # 1 year
```

2. Start the controller — it generates CA, server cert, and bootstrap token:

```bash
$ vpnctl controller init --config controller.yaml
Bootstrap token: vpnctl-bootstrap-a1b2c3d4e5f6...
```

3. Join nodes using the bootstrap token:

```bash
$ vpnctl node join --config node.yaml --token vpnctl-bootstrap-a1b2c3d4e5f6...
bootstrap ok node_id=node-a vpn_ip=10.7.0.2/32 pki_dir=/etc/vpnctl/pki
```

4. All subsequent commands automatically use mTLS:

```bash
$ vpnctl node serve --config node.yaml   # uses client cert from pki_dir
$ vpnctl ping --config node.yaml --all   # same
```

### Token management

```bash
vpnctl controller token create --config controller.yaml   # new token
vpnctl controller token list --config controller.yaml      # list active
vpnctl controller token revoke <token> --config controller.yaml
```

### Without mTLS

If the `pki:` section is omitted from the controller config, vpnctl runs in plain HTTP mode with no authentication (backward compatible).

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

## Installation

### From source

```bash
git clone https://github.com/timo-kang/vpnctl.git
cd vpnctl
make build
sudo cp vpnctl /usr/local/bin/
```

### With Docker

```bash
make docker
docker run -p 8443:8443 -v vpnctl-data:/var/lib/vpnctl vpnctl controller init --config /etc/vpnctl/config.yaml
```

### systemd

```bash
sudo cp vpnctl /usr/local/bin/
sudo mkdir -p /etc/vpnctl
sudo cp deploy/vpnctl-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpnctl-node
```

## Logging

vpnctl uses structured logging via Go's `log/slog`.

```bash
# Set log level (debug, info, warn, error)
VPNCTL_LOG_LEVEL=debug vpnctl node serve --config node.yaml

# JSON output (for log aggregation)
VPNCTL_LOG_FORMAT=json vpnctl node serve --config node.yaml
```

## Prometheus Metrics

### Controller

The controller exposes metrics at `/prom/metrics` (no authentication required for scraping):

```yaml
# prometheus.yml
scrape_configs:
  - job_name: vpnctl-controller
    static_configs:
      - targets: ['controller:8443']
    scheme: https
    metrics_path: /prom/metrics
    tls_config:
      insecure_skip_verify: true
```

Available metrics:
- `vpnctl_nodes_registered` — total registered nodes
- `vpnctl_nodes_online` — nodes seen within last 60s
- `vpnctl_direct_probes_total{node,peer,success}` — probe attempt counter
- `vpnctl_p2p_ready_pairs` — verified P2P peer pairs

### Monitor

Start monitor with `--metrics-port` to expose node-side metrics:

```bash
vpnctl monitor --interface wg0 --metrics-port 9090
```

Available metrics:
- `vpnctl_probe_rtt_seconds{peer}` — last probe RTT
- `vpnctl_probe_success{peer}` — last probe result (1/0)
- `vpnctl_probe_total{peer,result}` — probe attempt counter
- `vpnctl_link_quality{peer}` — link quality level (3=good, 2=degraded, 1=poor, 0=offline)
- `vpnctl_probe_loss_ratio{peer}` — recent probe loss ratio (0.0-1.0)

### Network Quality API

When running monitor with `--metrics-port`, a JSON endpoint is available:

```bash
$ curl http://localhost:9090/network/quality
[
  {"peer":"10.7.0.2","quality":"good","rtt_ms":8.2,"loss_pct":0},
  {"peer":"10.7.0.3","quality":"degraded","rtt_ms":120,"loss_pct":5.5}
]
```

Quality levels: `good` (RTT<50ms, loss<2%), `degraded` (RTT<200ms, loss<10%), `poor`, `offline`.

Robot applications can poll this endpoint to adapt video quality, message priority, or autonomy level based on current network conditions.

## License

Apache License 2.0. See [LICENSE](LICENSE).
