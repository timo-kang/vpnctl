# Application uplink status and reconnect contract (#29)

Status: implementation proposal. These endpoints and consumers do not exist yet.
This document scopes the next slices after observation-cost qualification.

VPN supplies one way for a robot without its own direct uplink to reach an
application server through a relay. This API describes network observations;
it does not control robot motion, missions, or the application's transactions.

## Producer and transport

Start with an opt-in, read-only Unix HTTP socket owned by one existing
`node relay target reconcile --watch` process, for that process's fixed target.
An API request reads a bounded in-memory snapshot; it never takes the relay
cache/kernel ownership lock or starts new probes. The existing observer is the
only producer. A slow subscriber must not delay lease maintenance or route
control. Multi-target aggregation can follow without making the controller a
required intermediary for a robot's local consumer.

Proposed operations:

- `GET /v1/status`: current snapshot for this socket's target.
- `GET /v1/events?after=<cursor>`: bounded change stream with snapshots, not
  deltas that require an unbounded replay history.

Use a separately provisioned runtime directory and socket, with restrictive
filesystem permissions and explicit allowed local UIDs verified by SO_PEERCRED.
Do not expose the controller administration socket, private cache, keys, peer
configuration, full candidate inventory, or mutation operations. Do not open a
TCP listener by default. Deployment prepares directory ownership/group access;
services do not gain a persistent chown or mount capability for the API. Clients
verify the expected server UID and protected parent-directory ownership before
trusting the socket; a replaced listener is not automatically a valid producer.

## Status semantics

Keep availability, observation freshness and session continuity separate:

| Field | Meaning |
| --- | --- |
| `schema_version` | Versioned public contract; start at 1. |
| `target_id` | The fixed, configured application target. |
| `producer_id`, `revision` | Random process incarnation and increasing publication revision. A new producer requires resynchronization. |
| `availability` | `reachable`, `unreachable`, `blocked`, or `unknown`; never inferred from controller connectivity alone. |
| `freshness` | `fresh`, `stale`, or `unknown`, recomputed at read time. |
| `reason` | Bounded machine-readable reason from an explicit allowlist. |
| `observed_age_ms`, `remaining_validity_ms` | Informational age and budget at serialization; neither starts a new TTL on receipt. |
| `clock_domain`, `valid_until_boot_ns` | Verified local boot/namespace domain and absolute `CLOCK_BOOTTIME` deadline. The consumer checks both at receipt and before use. |
| `path_id`, `path_revision` | Verified active path and local transition revision, when known. |
| `evidence` | Initially `unbound_tcp_connect`; not application protocol health. |
| `session_continuity` | Initially `not_established`; never promote this to `preserved` from a new connection's success. |
| `forecast` | Absent until a separately validated prediction is available. |

Only a completed, applied result with a verified active route and valid evidence
can publish reachable. A desired path, journal entry, recent heartbeat or
successful API response is insufficient. Missing/failed admission is unknown;
it cannot claim that quarantine was installed. Explicit denial/expiry is
blocked. Claim unreachable only from fresh negative evidence for the approved
candidate scope; distinguish unknown candidates from known unavailable paths.

The current reservation/catalog `generation` is not a route-change counter.
Introduce an explicit publisher transition revision. It changes after a switch,
rollback, quarantine/reactivation, or installation identity change, including
returning to the same path ID. A producer restart changes `producer_id` and
invalidates the old cursor before any fresh state is available. Do not infer
route equality from path ID alone or use wall-clock timestamps as counters.

An in-process producer must carry an actual monotonic/BOOTTIME validity budget
out of reconciliation; reconstructing authority from JSON timestamps is not
acceptable. For `reachable` and approved-scope `unreachable`, the exported deadline is
the minimum absolute observation and approval deadline. A newly observed
explicit denial/expiry publishes `blocked` with its own bounded observation
deadline; this reports a negative policy observation and cannot extend approval
or authorize traffic. Missing evidence publishes unknown without a reusable
validity budget. All fresh states become unknown/stale when their observation
budget expires, including blocked. An event can wait in a queue or socket after
serialization, so a
consumer must never start `remaining_validity_ms` at receipt. Instead it verifies
`clock_domain`, compares its current `CLOCK_BOOTTIME` with
`valid_until_boot_ns` at receipt and before use, and rejects already expired
evidence. Emit the nanosecond deadline as a decimal string to avoid JSON number
precision loss.

The initial local contract requires the same boot and network namespace and
zero monotonic/boottime time-namespace offsets on both sides, using the existing
`relayguard.Now` validation rule. Define the public domain as a versioned digest
of the boot ID and network-namespace device/inode identity, computed independently
by both sides; do not expose private approval witnesses or raw cache fields.
A mismatch, unavailable clock or unverifiable domain produces unknown status,
not a fallback to wall-clock TTL. The producer itself cannot authenticate the
clock domain supplied by a different host. Cross-host consumers need a separate
contract. Suspension, clock rollback, stopped publication, delayed delivery and
producer restart must never extend evidence validity. A changed producer also
invalidates old cursors and cached snapshots. A stale snapshot stays stale until
new evidence arrives. At or beyond the deadline, an old fresh
snapshot becomes `availability=unknown, freshness=stale`; retaining an old
`reachable` label must never authorize a current-state claim. A newly observed
explicit approval denial/expiry may publish `blocked`, which describes policy
unavailability and does not by itself prove installed kernel quarantine. API
liveness and data-path liveness are independent.

Linux BOOTTIME includes suspend, while time namespaces can offset BOOTTIME and
MONOTONIC; see the [Linux time-namespace contract](https://man7.org/linux/man-pages/man7/time_namespaces.7.html).

## Delivery and consumer behavior

A stream begins with a full snapshot. An unknown/expired cursor or queue overflow
returns an explicit reset plus the latest snapshot. Bound record size, retained
records, clients and per-client queues before implementation. Disconnect slow
readers; never block the producer. Bound both global and per-UID request rates,
concurrent handlers, active streams, parsing work and response bytes. Reject
excess requests with a bounded `429` response rather than queueing unbounded
work. An allowed fast reader must not starve reconciliation; include a request
flood in the resource and freshness qualification. Expiry must become observable
even if no new reconcile completes. Consumers handle duplicates, missing revisions, changed
producer IDs, truncated records, disconnection and their own freshness timeout.

Provide Go and Python examples. Each example maintains its own bounded connect,
read and write deadlines, reconnects with bounded exponential backoff and jitter,
and resets backoff only after an authenticated application response. Path events
can wake a retry; they are neither a command to migrate a healthy connection nor
proof that the connection survived. API loss does not prove data-path loss.
The samples report API availability and payload availability independently.

Use a nonce/request ID and require the server to echo that exact ID in the
sample protocol. Do not automatically replay arbitrary application operations.
If a connection fails after a request was sent, report outcome unknown unless
the application supplies its own idempotency/deduplication contract. Keep
`same_socket_recovered` separate from `new_socket_reconnected`.

## Implementation and completion slices

1. Pure status adapter and bounded snapshot store: validate versions/identity,
   map applied proof correctly, preserve fresh/stale/blocked/unknown distinctions,
   introduce route/producer revisions and suspend-aware validity. Prove expiry,
   rollback, delayed delivery, clock-domain mismatch, nonzero time-namespace
   offsets and repeated path-ID transitions with deterministic clocks. No new
   listener until this contract passes.
2. Opt-in Unix read API and bounded event delivery: authentication, safe runtime
   path handling, duplicate/reset/slow-client behavior and clean shutdown. Prove
   slow readers and request floods stay within explicit CPU/memory limits without
   delaying reconciliation or lease maintenance beyond its existing gates.
3. Go/Python reconnect consumers and a disposable VM matrix: same-relay underlay
   switch, relay switch, app-1-only uplink loss, all-uplink loss, recovery, API
   outage, producer restart and two independent apps. Include approval expiry
   and revocation while a consumer keeps retrying; no bypass or default fallback.
4. Record monotonic boundaries for injected fault, verified route change,
   publication, consumer receipt, connect and first correct payload. Report
   missing boundaries and right-censored recovery explicitly. Measure CPU cost,
   duplicates/loss and gaps after initial recovery. Select application-specific
   outage/reconnect budgets; the selector's 10-second freshness limit is not a
   universal application outage SLO.

All network and power fault experiments remain in owned disposable namespaces
or VM guests. No host Wi-Fi, network, clock, suspend or reboot changes are needed.
