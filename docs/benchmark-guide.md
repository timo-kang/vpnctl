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

## sockperf (latency + jitter)

Server (Node B):
```bash
sockperf server -i 10.7.0.12 -p 11111
```

Client (Node A, ping-pong):
```bash
# Example: 100Hz, 100B, 30s
sockperf ping-pong -i 10.7.0.12 -p 11111 -m 100 -t 30 --mps 100

# Example: 10Hz, 2000B, 30s
sockperf ping-pong -i 10.7.0.12 -p 11111 -m 2000 -t 30 --mps 10
```

Client (under-load):
```bash
# Example: 400Hz, 1000B, 30s
sockperf under-load -i 10.7.0.12 -p 11111 -m 1000 -t 30 --mps 400
```

CSV output:
```bash
sockperf ping-pong -i 10.7.0.12 -p 11111 -m 100 -t 30 --mps 100 --full-log /tmp/sockperf.csv
```

### Sample results (your runs)

| 시나리오 (부하 수준) | 타겟 노드 | 실험 회차 | 평균 지연(Avg Latency) | 안정성 지표(99th Percentile) | 표준 편차(Jitter) | 평가 |
|---|---|---|---|---|---|---|
| 1. 제어 신호(100Hz, 100B) | Office (12) | 1차 시도 | 28.9 ms | 61.2 ms | 9.9 ms | 보통 |
| 1. 제어 신호(100Hz, 100B) | Office (12) | 2차 시도 | 21.5 ms | 29.3 ms | 5.8 ms | 매우 우수 |
| 1. 제어 신호(100Hz, 100B) | Server (2) | - | 28.7 ms | 42.0 ms | 8.2 ms | 우수 |
| 2. 센서 데이터(10Hz, 2000B) | Office (12) | 1차 시도 | 39.9 ms | 212.6 ms | 27.0 ms | 위험 (Lag) |
| 2. 센서 데이터(10Hz, 2000B) | Office (12) | 2차 시도 | 26.2 ms | 37.8 ms | 4.5 ms | 최상 (Best) |
| 2. 센서 데이터(10Hz, 2000B) | Server (2) | - | 32.2 ms | 54.5 ms | 5.4 ms | 우수 |
| 3. 스트리밍(400Hz, 1000B) | Office (12) | 1차 시도 | 30.5 ms | 45.6 ms | 5.3 ms | 양호 |
| 3. 스트리밍(400Hz, 1000B) | Office (12) | 2차 시도 | 24.7 ms | 36.4 ms | 3.7 ms | 매우 우수 |
| 3. 스트리밍(400Hz, 1000B) | Server (2) | - | 31.2 ms | 48.5 ms | 7.5 ms | 양호 |
| 4. 극한 부하(Under-load) | Server (2) | - | 28.8 ms | 38.6 ms | 4.0 ms | 매우 안정적 |
