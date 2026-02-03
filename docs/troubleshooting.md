# Troubleshooting

## 1) No handshake / 0 bytes received
Symptoms:
- `wg show` on node shows 0 B received and no `latest handshake`.

Checks:
- Ensure server has `wg0` up and peers configured.
- Confirm UDP 51820 is open on server.

Server quick check:
```bash
sudo wg show
ip addr show wg0
```

## 2) Relay ping/perf timeouts
Symptoms:
- `ping --path relay` times out.

Checks:
- Ensure responder is running on peer (agent or `direct serve`).
- Ensure firewall allows UDP on `probe_port` (default 51900) on `wg0`.

Firewall examples:
```bash
# iptables: allow probe traffic on wg0
sudo iptables -I INPUT -i wg0 -p udp --dport 51900 -j ACCEPT

# ufw: allow probe traffic on wg0
sudo ufw allow in on wg0 to any port 51900 proto udp
```

Quick responder:
```bash
go run ./cmd/vpnctl direct serve --listen :51900
```

## 3) Direct path missing
Symptoms:
- `public_addr` is empty in `discover`.
- `ping --path direct` says missing address.

Checks:
- Ensure `node run` is active (STUN runs there).
- Ensure STUN servers are configured.
- Confirm outbound UDP allowed.

## 4) Internet lost on node
Symptoms:
- Local internet dies after `up` or `node run`.

Checks:
- `server_allowed_ips` should be the VPN subnet (not 0.0.0.0/0).
- `policy_routing_cidr` must be scoped (e.g., `10.7.0.0/24`).

Cleanup:
```bash
sudo ip rule del pref 1000 lookup 51820
sudo ip route flush table 51820
sudo ip link del wg0
```

## 5) `sync-config` 500 errors
Common causes:
- Controller cannot write to `data_dir`.
- Controller missing `server_*` fields (for wg-config).

Fix:
- Run controller as root or use a writable `data_dir`.
- Ensure `server_public_key`, `server_endpoint`, and `server_allowed_ips` are set.
