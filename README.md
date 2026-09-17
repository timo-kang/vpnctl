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

## Address allocation (IPAM)

The controller keeps one stable `/32` VPN lease per node identity. The current
registration API uses `name` as that identity. Re-registering, restarting, or
reissuing a certificate with the same name preserves its lease. A renamed node
is a new identity; remove the old node to release its lease. Removal permanently
blocks the old identity, including bootstrap and existing certificates. To replace
a lease, remove the old identity and enroll a new name. The controller rejects
duplicate, malformed, out-of-CIDR, network, and broadcast addresses.

`controller.wg_address` is always reserved. Additional individual addresses or
CIDR ranges can be excluded with `reserved_vpn_ips`:

```yaml
controller:
  vpn_cidr: "10.7.0.0/24"
  wg_address: "10.7.0.1/24"
  reserved_vpn_ips:
    - "10.7.0.10"
    - "10.7.0.16/28"
```

At startup, vpnctl normalizes legacy host addresses to `/32` and refuses to
start if the existing registry contains duplicate, reserved, malformed, or
out-of-range leases. Back up and correct `registry.yaml` before restarting;
vpnctl does not silently reassign an address because node-side configuration
would otherwise disagree with the controller.

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
    server_renew_before: "720h"
    client_renew_before: "720h"
    check_interval: "1m"
    ca_overlap: "24h"
    server_sans:             # SANs for the server cert (required if listen is 0.0.0.0)
      - "controller.example.com"
      - "10.10.10.1"
      - "1.2.3.4"
```

**Note**: When `listen` is `0.0.0.0` (all interfaces), you **must** set `server_sans` to the IPs/hostnames clients will use to connect. If `server_sans` is omitted, the server cert defaults to `127.0.0.1` and `localhost` only, which works for local testing but fails for remote nodes.

If you change `server_sans` later, the server certificate is regenerated automatically on next controller start. The CA stays the same, so existing client certs remain valid.

2. Start the controller — it generates CA, server cert, and bootstrap token:

```bash
$ vpnctl controller init --config controller.yaml
Bootstrap token: vpnctl-bootstrap-a1b2c3d4e5f6...
```

3. Export the public CA bundle on the controller host, then deliver it to each
node over an authenticated provisioning channel (for example, SSH with a verified
host key). Bootstrap requires this trust anchor before sending the token:

```bash
$ vpnctl controller pki trust --config controller.yaml > controller-ca.pem
```

Join the node with the token and the provisioned bundle:

```bash
$ vpnctl node join --config node.yaml --token vpnctl-bootstrap-a1b2c3d4e5f6... --ca-cert controller-ca.pem
bootstrap ok node_id=node-a vpn_ip=10.7.0.2/32 pki_dir=/etc/vpnctl/pki
```

4. All subsequent commands automatically use mTLS:

```bash
$ vpnctl node serve --config node.yaml   # uses client cert from pki_dir
$ vpnctl ping --config node.yaml --all   # same
```

Each newly issued client certificate contains a controller-assigned identity in
the URI SAN `vpnctl://node/<node-id>`. The controller binds that identity to
node-scoped API fields such as `name` and `node_id`; a certificate for one node
cannot register or report state for another node.

Certificates issued by older vpnctl versions contain only a Common Name. They
remain usable during migration and produce a controller warning containing the
certificate fingerprint. Re-enroll each warned node with its existing
`node.name` and a fresh bootstrap token:

```bash
$ vpnctl controller token create --config controller.yaml
$ vpnctl node join --config node.yaml --token <new-bootstrap-token> --ca-cert controller-ca.pem
```

Re-enrollment atomically replaces `credentials.json` in `node.pki_dir` and
preserves the registered VPN IP. Running clients reload complete credential
changes on their next request. Legacy `ca.crt` / `client.crt` / `client.key` files
are imported on the first successful PKI sync. A configured `pki_dir` requires
HTTPS and valid credentials; it never falls back to plain HTTP.
If `node.name` must change, enroll it as a new identity instead of reusing the
old certificate.

### Controller administration

Management commands contact the running controller over a local Unix socket at
`<controller.data_dir>/run/admin.sock`. Run them on the controller host with the
same data directory and OS user (or root). Prefer an absolute `data_dir`; relative
paths must resolve from the same working directory. The socket is mode `0600`; its real,
controller-owned `run` directory must be mode `0700`. Linux peer credentials
identify the caller. The TCP API does not expose this management endpoint.

The controller locks its data directory before loading state or initializing PKI.
A second controller using the same directory fails before changing state. A
restart recovers a leftover socket after acquiring the lock. Keep `data_dir` on a
local filesystem that supports Unix sockets, `flock`, and atomic rename.

Commands fail when the controller is stopped; they never fall back to editing
files. Do not edit live registry/token files or delete the lock file. For offline
recovery, stop the controller, back up the whole data directory (including PKI and
`removed_nodes`), restore consistent state, then restart. Do not remove deletion
records to reuse an identity: its old certificates would regain authorization.

```bash
vpnctl controller remove-node --name node-a --config controller.yaml
```

Successful removal commits the registry deletion and a permanent identity
revocation record, releases the VPN lease, removes direct readiness and current
node/peer metric labels, and removes the node from fleet/candidates responses.
Historical CSV samples remain available. Repeated removal of an already removed
identity succeeds. Existing certificates for that identity cannot access any
protected node/fleet API; bootstrap and plain-mode registration/reporting also
reject the removed identity. Enroll a new `node.name` to replace the device.
Individual certificate revocation, renewal and CA rotation are managed by
`controller pki`; see the lifecycle section below.

With `wg_apply: true`, removal replaces the controller's WireGuard peer set
before acknowledging success. Apply or registry-save failure returns an error
and attempts to restore the previous peer set; rollback failure is logged as well.
With `wg_apply: false`, only controller state changes. Remote agents remove cached
direct peers after a successful candidates refresh and direct reconciliation;
an agent disconnected from the controller can retain stale peers. This command
does not promise immediate packet isolation across a partitioned mesh.

Controller SIGTERM/SIGINT closes admission and drains accepted mutations before
releasing the state lock. External ip/wg commands have a 5-second timeout and WG
mutations a 30-second budget; rollback gets a fresh budget. The 10-second HTTP
shutdown grace closes client connections but never releases ownership while a
handler may still write. See the [shutdown and recovery runbook](docs/validation/controller-lifecycle.md)
for process-group cleanup, verification and force-stop limits.

### Token management

```bash
vpnctl controller token create --config controller.yaml   # reusable, expires in 24h
vpnctl controller token create --config controller.yaml --ttl 30m --single-use
vpnctl controller token create --config controller.yaml --ttl 0s  # explicit no expiry
vpnctl controller token list --config controller.yaml      # active tokens
vpnctl controller token list --config controller.yaml --json # policy + admission history
vpnctl controller token revoke <token> --config controller.yaml
```

Creation and revocation take effect without restarting. Revocation waits for an
already admitted enrollment to finish; after it returns successfully, no new
enrollment can use that token. It does not revoke certificates already issued.

Single-use consumption is persisted before enrollment changes the registry.
Concurrent requests admit at most one attempt. A subsequent registration failure,
crash, or lost response still consumes the token; create a new token and retry.
`use_count` counts admitted attempts, not certificates successfully delivered.
JSON history retains creation/expiry/revocation times, usage count and the last
admitted node/time, including expired, consumed and revoked tokens. Token values
in this local output are secrets. Audit logs record actor UID/PID, operation,
result and target; tokens are represented by a SHA-256 identifier, never plaintext.

First-time PKI initialization creates a reusable 24-hour token. Restarting with
an existing empty or fully revoked/expired store does not generate a new token.
Legacy JSON string arrays load as reusable, non-expiring records and migrate to
the versioned format on mutation. Back up before upgrading: older binaries cannot
read the new token format or enforce removed-identity records.

A management timeout does not establish whether a mutation committed. Inspect
`controller status` or `token list --json`; removal and revocation can safely be
retried. Token creation retries may create another token, so inspect and revoke
any unused token after a lost response.

### Certificate lifecycle

`node run` and `node serve` automatically refresh trust and renew their client
certificate before expiry. The controller renews its server certificate and
loads the current certificate/trust snapshot at every new TLS handshake.
Renewal defaults to the last third of the configured client/server lifetime;
`client_renew_before` and `server_renew_before` override those windows. Windows
must be at least one second and shorter than their lifetimes. `check_interval`
controls controller maintenance and must be shorter than both windows.

Node sync runs at most one minute apart and more often as expiry approaches.
Failures use bounded exponential retry, capped at one minute and shortened by
the remaining lifetime. The node persists a pending CSR/key before requesting
renewal. Retries use the same CSR and recover the same signed certificate after
response loss or process restart. A parent certificate can issue one renewal
per signing CA, within its renewal window or immediately after a CA switch.
An already expired or revoked certificate requires administrator-assisted
bootstrap with a fresh token and a trusted CA bundle.

```bash
vpnctl controller pki status --config controller.yaml
vpnctl controller pki revoke --fingerprint <sha256> --config controller.yaml
vpnctl controller pki ca-prepare --config controller.yaml
vpnctl controller pki ca-activate --config controller.yaml
vpnctl controller pki ca-retire --config controller.yaml
vpnctl controller pki ca-rollback --config controller.yaml
```

`status` lists identity, serial, fingerprint, validity, revocation, trust generation
and per-node acknowledgements. Certificate revocation takes effect on every
protected API, including already established TLS connections. Other certificates
for the same identity remain valid; use `remove-node` for a lost or compromised
device.

CA replacement is staged: prepare publishes both roots while continuing to sign
with the old one; activate requires all registered nodes to acknowledge persisted
trust; retire requires the configured overlap period and acknowledgements using
the active CA's client certificates. Missing or expired acknowledgements block
progress. Rollback before activation cancels preparation. Rollback after activation
switches signing back while retaining both roots until nodes have migrated back
and the overlap can be retired. CA retirement is an explicit operator action.

```bash
vpnctl controller pki backup --config controller.yaml --out controller-backup.json
vpnctl controller pki restore --file controller-backup.json \
  --data-dir /var/lib/vpnctl-restored --config-out restored-controller.yaml
```

Backups include controller configuration, registry, token history and the complete
PKI authority/revocation/renewal state. They contain private keys and are written
with mode `0600`. Restore requires a fresh directory and prevents startup until
all files are installed; an interrupted restore can resume with the same backup.
The [PKI runbook](docs/pki-lifecycle.md) covers rollout gates, recovery, key exposure,
legacy migration, metrics and the exact availability guarantees.

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

# Node agent
sudo cp deploy/vpnctl-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpnctl-node

# Network monitor (optional, enables /network/quality API on port 9090)
sudo cp deploy/vpnctl-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpnctl-monitor
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

## Status Page

The controller serves a built-in HTML status page at `/status` (no authentication required):

```
http://controller:8443/status
```

Shows all registered nodes with online/offline status, quality level, and last seen time. Auto-refreshes every 5 seconds.

## Grafana Dashboard

Import the pre-built dashboard for Prometheus + Grafana:

```
Grafana → Dashboards → Import → deploy/grafana/vpnctl-dashboard.json
```

Panels: nodes online/offline, RTT time series, loss ratio, link quality table/timeline, probe rates.

## License

Apache License 2.0. See [LICENSE](LICENSE).

### Kernel WireGuard reliability checks

`make test-netns` builds the current CLI with the race detector and runs isolated
Docker network namespaces with 1, 3, 8 and 32 nodes. It measures UDP/TCP application
uplink and mTLS API availability during automatic renewal, CA rotation/rollback,
revoked-credential replay, packet loss and controller/node restarts.

Use `VPNCTL_NETNS_SIZES=1,8` to select fleet sizes, or pass `-test.count=3` to
`./scripts/test-netns.sh` for repetitions. Results are saved under the printed
`/tmp/vpnctl-netns-results.*` directory (or `VPNCTL_ARTIFACT_DIR`). See the
[reproduction procedure and acceptance criteria](docs/validation/wireguard-pki-gate.md).
The [API latency investigation](docs/validation/api-latency.md) describes the
slow-reconciliation regression, HTTP stage traces, CPU/resource artifacts and
the limits of the verified fleet sizes.

A provisioned `node serve` restores its saved WireGuard path before contacting
the controller, allowing a controller URL reachable only through the VPN. Initial
enrollment still needs a provisioning path and a trusted CA bundle.
