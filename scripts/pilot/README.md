# Manual pilots

Ad-hoc experiments that answer a single feasibility question. **Not run by
`make test-netns` or CI.** Kept here as reproducible evidence for a claim and as
a starting seed for future work.

## `pilot-multihop.sh`

Answers: *"Can the vpnctl netns harness host multi-hop WireGuard forwarding
where a middle node relays for two isolated endpoints, without any change to
controller/agent Go code?"*

**Answer (2026-09-25): yes**, with static config only.

### Setup

Three network namespaces (`nA`/`nB`/`nC`) with veth pairs A↔C and B↔C, no
direct A↔B underlay. WireGuard overlay `10.7.0.0/24` where A=`.1`, B=`.2`,
C=`.3`. C enables `net.ipv4.ip_forward=1`. A/B `AllowedIPs` list the remote
endpoint on the C peer entry, so the kernel routes A→B traffic through C's
`wg0` where it is decrypted, forwarded, and re-encrypted for B.

### Result

| Test | Result |
|---|---|
| A→C single hop, 10 pings | 10/10, RTT avg 0.28 ms |
| A→B multi-hop, 100 pings | 100/100, 0% loss, RTT avg 0.33 ms |
| B→A multi-hop, 100 pings | 100/100, 0% loss, RTT avg 0.34 ms |
| Negative control: `ip_forward=0` | ping fails (proves forwarding dependency) |
| Recovery: `ip_forward=1` again | 20/20, 0% loss |

`wg show` on C confirmed non-zero rx/tx on both peer entries.

### Run

```bash
docker build -t vpnctl-pilot-multihop tests/integration
docker build -t vpnctl-pilot-multihop:v2 -f scripts/pilot/pilot-multihop.Dockerfile .
docker run --rm --init --network none --privileged \
  -v "$(pwd)/scripts/pilot/pilot-multihop.sh:/pilot.sh:ro" \
  --entrypoint /bin/bash \
  vpnctl-pilot-multihop:v2 /pilot.sh
```

Runs in ~40 seconds. Requires `--privileged` because the base image mounts
`/proc/sys` read-only; a fuller integration would use
`--sysctl net.ipv4.ip_forward=1` per netns instead.

### What's missing before this becomes a real feature

- Controller logic to compute next-hop tables and distribute them
- Node agent applying next-hop `AllowedIPs` updates via existing peer sync
- Loop detection and route-flap dampening
- Multi-path (multiple candidate relays per destination)
- Wiring into `make test-netns` at fleet sizes 8/32 with `tc netem` loss
