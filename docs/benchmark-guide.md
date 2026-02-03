# Benchmark Guide (Controller + 2 Nodes)

This guide walks through repeatable benchmarks for hub-only vs direct routing.

## Assumptions
- Controller has a public IP and is reachable by nodes.
- Nodes are Linux with 5G SIMs.
- WireGuard keys exist for each node and the server.

## 1) Config setup

Controller (`configs/controller.yaml`)
```yaml
controller:
  listen: "0.0.0.0:8443"
  data_dir: "/var/lib/vpnctl"
  server_public_key: "<server-public-key>"
  server_endpoint: "<server-public-ip:51820>"
  server_allowed_ips:
    - "10.7.0.0/24"
  server_keepalive_sec: 25
  vpn_cidr: "10.7.0.0/24"
```

Node A (`configs/node-a.yaml`)
```yaml
node:
  name: "node-a"
  controller: "<controller-public-ip:8443>"
  wg_interface: "wg0"
  wg_config_path: "/etc/wireguard/wg0.conf"
  wg_private_key: "<node-a-priv>"
  wg_public_key: "<node-a-pub>"
  mtu: 1280
  direct_mode: "auto"
  policy_routing_enabled: true
```

Node B: same, with name + keys.

## 2) Bring up

Controller:
```bash
go run ./cmd/vpnctl controller init --config configs/controller.yaml
```

Each node:
```bash
# Pull vpn_ip + server_* fields and write back
go run ./cmd/vpnctl node sync-config --config configs/node-a.yaml

# Bring up WG (requires root)
sudo go run ./cmd/vpnctl up --config configs/node-a.yaml

# Start agent loop (STUN + direct probing + peer injection)
go run ./cmd/vpnctl node run --config configs/node-a.yaml
```

Check status:
```bash
go run ./cmd/vpnctl status --config configs/node-a.yaml
```

## Scenario A — Hub-only (relay)

Force relay by disabling direct.
```yaml
node:
  direct_mode: "off"
  policy_routing_enabled: true
```

Run:
```bash
go run ./cmd/vpnctl ping --config configs/node-a.yaml --peer node-b --count 200 --interval 100ms
go run ./cmd/vpnctl perf --config configs/node-a.yaml --peer node-b --count 500 --size 1200
```

## Scenario B — Direct-if-possible (auto)

Enable direct mode:
```yaml
node:
  direct_mode: "auto"
  policy_routing_enabled: true
```

Run the same ping/perf. If NAT allows, you should see `/32` peers in `wg show`.

## Scenario C — Policy routing off

```yaml
node:
  direct_mode: "auto"
  policy_routing_enabled: false
```

Direct probes may succeed, but routing stays on relay.

## Metrics

Summarize last 10 minutes:
```bash
go run ./cmd/vpnctl stats --config configs/node-a.yaml --window 10m
```

Export CSV:
```bash
go run ./cmd/vpnctl export csv --config configs/node-a.yaml --out /tmp/metrics.csv
```

## iperf (throughput + latency)

Throughput (TCP):
```bash
# Node B (server)
iperf3 -s -B 10.7.0.12

# Node A (client)
iperf3 -c 10.7.0.12 -t 30 -P 4 -i 1
```

Reverse direction (Node B -> Node A):
```bash
iperf3 -c 10.7.0.12 -t 30 -P 4 -i 1 -R
```

Latency (RTT):
```bash
ping -c 50 -i 0.1 10.7.0.12
```

UDP loss/jitter (optional):
```bash
iperf3 -c 10.7.0.12 -u -b 20M -t 30 -i 1
```

Notes:
- Binding to the VPN IP forces traffic over `wg0`.
- For machine-readable output, add `-J` and parse JSON.
