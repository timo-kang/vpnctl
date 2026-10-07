# Actual manager automatic switching matrix

This is the #175 extension of [manager coexistence](network-manager-coexistence.md).
The robot runs the real automatic selector, candidate preparation supervisor and
application route reconciler. Controller, two relays and targets use separate
network namespaces in an identity-guarded guest. Four/eight candidates mean two
relays × two/four approved virtual Ethernet underlays. The independent second
application is pinned to relay 1 / underlay 1 to detect unintended disruption.

The pinned application's reconcile loop probes only candidates its immutable
selection policy permits. Its other seven candidates in the eight-path profile
remain visible as policy exclusions, and every candidate still receives lease
maintenance and revocation enforcement. Probing all eight for a manual pin held
the shared FIFO lock long enough to reset an unaffected application's 10-second
health history on a slower runner (#183). The full automatic candidate sweep,
freshness thresholds, lease deadlines and all traffic assertions are unchanged.

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

`VPNCTL_VM_CPUS=0.5` or `0.25` reduces only the test container's CPU quota for
contention experiments; the default remains one CPU. Both the source manifest
and isolation report record the quota. Guest clocks, lease deadlines, probe
timeouts and convergence limits are unchanged. This is CPU pressure testing,
not a claim that throttling reproduces a particular runner's instruction speed.

## Scenarios and functional requirements

The matrix performs NM profile down/up, relay uplink loss, all-relay loss,
alternate and preferred recovery, NM restart, Netplan apply, networkd restart,
foreign firewall reload, two repeated down/up cycles, NM shared DHCP/NAT,
foreign WG peer conflict/removal, application watcher restart, controller loss,
real approval expiry, fresh-approval-only continued blocking, and recovery after
explicit relay installation with fresh approval. Manager operations and synthetic
kernel faults are distinguished by each step's `origin` field.

Relay supervision renews already installed endpoints; it does not retain an
installation intent after approval expiry removes them ([follow-up #178](https://github.com/timo-kang/vpnctl/issues/178)). Fresh approval alone
must leave those absent endpoints blocked. The final recovery explicitly runs
`relay apply` with the existing matching local key; only node candidate rebuilding
and application path selection recover automatically. This is a deployment
boundary, not end-to-end automatic relay reinstallation qualification.

No failure is repaired by manually selecting the application's path. Selection
uses two fresh confirmations, a 10-second recovery hold-down and 15-second
minimum dwell; unhealthy paths can be left immediately. Candidate probes use the
product default one-second timeout. An earlier 150ms experiment produced a
transient timeout on an unchanged path and correctly triggered fail-closed
quarantine; it is retained as failed evidence, not the production profile. These are the matrix's
explicit policy parameters, not changed production defaults. Recreated underlay
generations must re-confirm eligibility. LAN/EtherCAT links remain excluded.

Each converged route requires ordinary TCP and UDP nonce payloads with the
server-observed relay source, an actual unbound route lookup, and nonzero WG
handshake/RX/TX. RF/gimbal LAN traffic and the independent application are sampled
concurrently. LAN failures, or independent-app failures during an unaffected
phase, fail the test. The explicit `netplan-apply` phase directly reconfigures
RF/gimbal LANs: only LAN failures bracketed by that command's start and verified
LAN recovery are reported separately. Recovery requires real nonce replies with
the original sources and original LAN route/device readback within a five-second
fixture watchdog after command completion. Failure counts and monotonic proof
times remain in `lan_reconfiguration`; later LAN failures and independent-app
failures still fail the scenario. A pass does not mean Netplan apply is lossless.
This distinction follows [systemd v255 forced reconfiguration](https://github.com/systemd/systemd/blob/v255/src/network/networkd-link.c#L1134),
which drops managed configuration before restoring it. VPN switching phases have
no such exception (#184). NM shared DHCP uses real DORA and its allocated address,
then verifies shared NAT using an independent LAN payload. Manager configuration
hashes, foreign policy routes/rules and foreign peers must be preserved.

A lower-priority, application-only rule leads to a separate default-route table
that bypasses the relay network. All-unavailable and expired-approval phases
must block new payload instead of falling through to it. Explicit target release
at the end must demonstrate that this otherwise reachable fallback works. The
management NIC's default route remains intact. Other VPN/firewall resources are
synthetic ownership fixtures, not a claim about every third-party VPN product.

## Timing, TCP semantics and evidence

The outer runner's legacy `mode` option applies to its lease/power cases; manager
cases keep supervisors running and describe intentional process stops in their
individual steps. `qualified=true` means this functional matrix completed, not
that a p95 or an end-to-end deployment SLO passed.

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
wait interval is recorded separately. Both application watchers must finish two
distinct ready cycles started after all fixture policy changes; rereading old
successful logs for a few seconds cannot satisfy that barrier. Manager profiles
activate before the two application watchers start; the real node supervisor must rebuild any invalidated
bootstrap candidates within 120 seconds, verified by device-bound payload. All
measured manager faults run with both application watchers active. Complete public
preparation reports from the last 32 supervisor cycles accompany failure
diagnostics, including failures before packet tracing begins.
Candidate rebuilding admits up to eight fast durable units per FIFO turn within
its existing 750ms shared budget and 500ms reserve for each additional unit.
This avoids rejoining two busy application watchers after every pair of tiny
operations; slow operations retain the same deadline and yielding conditions.
The 120-second convergence watchdog is unchanged.
The durable round-robin cursor shares the unit's state/owner/in-flight commit;
a cursor-only fsync must not consume this bounded work quantum. Tests read back
the owner, cursor and in-flight marker before every kernel add and inject errors
before/after every dynamically traced journal write.

Keeping an already active route uses its exact current decision fingerprint and
underlay generation followed by a fresh unbound application TCP proof, with
live approval/lease/inventory/ownership/routes checked before and after it. It
does not run a second bound candidate TCP proof after the observation wave.
Changing or rolling back a route retains bound candidate revalidation before
mutation. Duplicate middle lease reads are removed; every proof boundary still
reads the live gates. This reduces lock contention without extending authority.
This clock excludes suspend; these scenarios do not suspend. These diagnostics
never authorize communication or replace BOOTTIME lease enforcement.
`observation_complete`, `decision_complete`, `target_routes_applied`,
`target_routes_blocked`, `application_verified` and `application_committed` denote
completed boundaries. Candidate/application revalidation failures also have
explicit checkpoints. Safety quarantine can precede the next no-path selection
decision; the timeline preserves this order. Rollback checkpoints are separately named. Successful
route installation alone is not first-payload success. Failover SLO uses the
first successfully applied approved alternative with a matching ordinary nonce
reply within that route's lifetime (`failover_path`/`failover_timeline`). Later
return to the preferred candidate after dwell/hold-down remains separately
recorded in `timeline`. Intermediate healthy paths must not be counted as
outage until preferred-path convergence. The observer checks the reported SLO
duration against the corresponding monotonic timestamps. The approval cutoff
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

Individual failovers and conclusive all-candidate failure for the server target
are compared with the existing 10-second budgets. `no_verified_path` is the
required no-uplink proxy, not a diagnosis of physical links. A guarded `unknown`
or `blocked` state proves safe quarantine only: `no_uplink_timeline` leaves its
conclusive decision absent and that SLO is `unmeasured`. In this mixed matrix,
wan0 candidate rebuilding can leave unknown entries while both relay uplinks
are down; that must not be published as a successful no-uplink deadline. The
earlier empty-selection timing remains in `timeline` for quarantine diagnostics. SLO misses and missing timing are recorded as `fail` and
`unmeasured`; functional completion does not relabel them as SLO success.
`p95_status=unqualified_insufficient_samples` is mandatory for this small matrix.
A p95 study needs at least 20 measured transitions per event class and profile,
all failures, an explicit observation horizon, and the same resource/traffic
conditions. Aggregating different fault classes or candidate sizes cannot prove
that SLO. This matrix alone does not close M3 or #24.

Physical Wi-Fi/AP/roaming, LTE modem behavior, DHCP uplink renewal, other Netplan
renderers, EtherCAT frames/deadlines and fleet operating SLOs need separate
hardware/deployment evidence.

## Rebuild cost under contention

A failed post-merge 8-candidate run (CI 37563690087) recovered traffic through
p01 but exceeded the unchanged 120-second preferred-path convergence limit.
Increasing the maximum work count alone did not help when each preparation unit
spent its budget collecting all four underlays. Preparation now collects fresh
inventory for the requested candidate's underlay, including the approved endpoints
on that underlay, while retaining the complete catalog and its original resource
slots. Full underlay configuration validation, current approval checks, kernel
ownership checks and per-unit persistence remain required. Inventory is never
reused between work units. Lease maintenance still checks every installed path
before rebuilding.

Node supervision reports include bounded `diagnostics.phases` for admission,
maintenance, rebuild, rebuild units and rebuild inventory, with elapsed time and
external command counts. Phase times are nested and must not be summed as wall
time. These fields are cost evidence only, never authorization or SLO proof.
The rebuild's 750ms shared wall/BOOTTIME budget, 500ms next-unit reserve, maximum
eight units and outer 5-second maintenance limit are unchanged.
