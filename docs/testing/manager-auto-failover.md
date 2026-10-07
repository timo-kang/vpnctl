# Actual manager automatic switching matrix

This is the #175 extension of [manager coexistence](network-manager-coexistence.md).
The robot runs the real automatic selector, candidate preparation supervisor and
application route reconciler. Controller, two relays and targets use separate
network namespaces in an identity-guarded guest. Four/eight candidates mean two
relays × two/four approved virtual Ethernet underlays. The independent second
application is pinned to relay 1 / underlay 1 to detect unintended disruption.

```sh
VPNCTL_ARTIFACT_DIR=/absolute/new-empty-results ./scripts/test-manager-auto.sh
# Independent repeats: each case boots a fresh disposable VM.
VPNCTL_ARTIFACT_DIR=/absolute/another-empty-results ./scripts/test-manager-auto.sh \
  --case manager-auto-4 manager-auto-8 manager-auto-4 manager-auto-8
```

The same KVM prerequisites, package versions, isolation guard and bounded
network-none container contract as the manual matrix apply. All NM, Netplan,
networkd, udev, nft and route commands affect only the guest. The host's Wi-Fi,
kernel modules, network, clocks and power state are never test targets. Each
invocation gets a new artifact directory; failed experiments remain available.

## Scenarios and functional requirements

The matrix performs NM profile down/up, relay uplink loss, all-relay loss,
alternate and preferred recovery, NM restart, Netplan apply, networkd restart,
foreign firewall reload, two repeated down/up cycles, NM shared DHCP/NAT,
foreign WG peer conflict/removal, application watcher restart, controller loss,
real approval expiry, fresh-approval-only continued blocking, and recovery after
explicit relay installation with fresh approval. Manager operations and synthetic
kernel faults are distinguished by each step's `origin` field.

Relay supervision renews already installed endpoints; it does not retain an
installation intent after approval expiry removes them. Fresh approval alone
must leave those absent endpoints blocked. The final recovery explicitly runs
`relay apply` with the existing matching local key; only node candidate rebuilding
and application path selection recover automatically. This is a deployment
boundary, not end-to-end automatic relay reinstallation qualification.

No failure is repaired by manually selecting the application's path. Selection
uses two fresh confirmations, a 10-second recovery hold-down and 15-second
minimum dwell; unhealthy paths can be left immediately. These are the matrix's
explicit policy parameters, not changed production defaults. Recreated underlay
generations must re-confirm eligibility. LAN/EtherCAT links remain excluded.

Each converged route requires ordinary TCP and UDP nonce payloads with the
server-observed relay source, an actual unbound route lookup, and nonzero WG
handshake/RX/TX. RF/gimbal LAN traffic and the independent application are sampled
concurrently. LAN failures, or independent-app failures during an unaffected
phase, fail the test. NM shared DHCP uses real DORA and its allocated address,
then verifies shared NAT using an independent LAN payload. Manager configuration
hashes, foreign policy routes/rules and foreign peers must be preserved.

A lower-priority, application-only rule leads to a separate default-route table
that bypasses the relay network. All-unavailable and expired-approval phases
must block new payload instead of falling through to it. Explicit target release
at the end must demonstrate that this otherwise reachable fallback works. The
management NIC's default route remains intact. Other VPN/firewall resources are
synthetic ownership fixtures, not a claim about every third-party VPN product.

## Timing, TCP semantics and evidence

`manager-auto` in the VM verdict contains a schema-2 report, every scenario,
bounded packet and application-cycle traces, final inventory and diagnostics.
Capacity overflow, truncation, missing clocks, omitted phases or nonzero test
exit cannot pass. Raw private config, certificates, cache and WG keys remain in
the private VM work directory and are not exported.

All packet timestamps, fault-command beginnings, command completions and product
execution checkpoints use the same guest boot's Linux `CLOCK_MONOTONIC` domain.
An observation's log receipt time is separate from its recorded execution time.
A command's start/completion brackets the injected event; the start is a
conservative latency origin, not a claim about an exact kernel notification.
Cycles already running at fault start retain their later checkpoints. Initial
manager setup must settle with all candidates confirmed before measurement; its
wait interval is recorded separately.
This clock excludes suspend; these scenarios do not suspend. These diagnostics
never authorize communication or replace BOOTTIME lease enforcement.
`observation_complete`, `decision_complete`, `target_routes_applied`,
`target_routes_blocked`, `application_verified` and `application_committed` denote
completed boundaries. Rollback checkpoints are separately named. Successful
route installation alone is not first-payload success. The approval cutoff
conversion from wall expiry to monotonic is explicitly an estimate.

- `tcp-new`: a new ordinary socket and random nonce for every attempt.
- `tcp-existing`: one socket established before each applicable fault, with an
  explicit session ID; no reconnect during that scenario. Partial replies and
  outstanding nonces survive read timeouts. The send timestamp distinguishes a
  delayed old response from a fresh post-expiry exchange. A new socket for a later
  scenario never counts as the old session surviving.
- `udp`: a fresh ordinary UDP socket and nonce per attempt. This is transaction
  reachability, not a claim of UDP stream continuity or packet-loss percentage.
- Each phase records successes/failures and maximum intervals between successes.
  Existing TCP's outcome is verified same-socket payload or no post-convergence
  reply within the recorded observation window. Different relay SNAT identities
  can break an existing TCP session even when new connections recover.

Individual failovers and all-unavailable detection are compared with the existing
10-second budgets. SLO misses and missing timing are recorded as `fail` and
`unmeasured`; functional completion does not relabel them as SLO success.
`p95_status=unqualified_insufficient_samples` is mandatory for this small matrix.
A p95 study needs at least 20 measured transitions per event class and profile,
all failures, an explicit observation horizon, and the same resource/traffic
conditions. Aggregating different fault classes or candidate sizes cannot prove
that SLO. This matrix alone does not close M3 or #24.

Physical Wi-Fi/AP/roaming, LTE modem behavior, DHCP uplink renewal, other Netplan
renderers, EtherCAT frames/deadlines and fleet operating SLOs need separate
hardware/deployment evidence.
