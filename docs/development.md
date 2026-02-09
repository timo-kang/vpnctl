# Development Notes

## Integration Tests (Linux netns)

There is an integration test that spins up a controller + 2 nodes in Linux network namespaces and checks
that direct WireGuard peer injection occurs.

Requirements:
- Linux
- root
- `ip` (iproute2)
- `wg` (wireguard-tools)

Run:
```bash
cd vpnctl
sudo VPNCTL_INTEGRATION=1 go test -tags=integration ./tests/integration -run TestNetns_DirectInjection -v
```

Notes:
- The test creates temporary network namespaces and a Linux bridge with names prefixed `vpnctl-`.
- If the test crashes, you may need to clean up manually:
  - `ip netns list | rg vpnctl`
  - `ip netns del <name>`
  - `ip link del <bridge>`

