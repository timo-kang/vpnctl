# Controller API latency and fault isolation

Scope: M1 #39, based on main `be51dbf`. The original 32-node Actions failure
(34946555633) had 287 HTTPS 1-second deadline errors while application UDP/TCP
continued to work. It did not capture request stages or CPU/IO contention, so
its exact historical trigger cannot be established retrospectively. This report
separates that uncertainty from the bottleneck reproduced and corrected here.

## Reproduced bottleneck

`registerNode` held the registry mutex across ip/wg execution, registry fsync,
and rollback. Certificate identity checks (`nodeRegistered`) and fleet snapshots
needed that same mutex. Consequently a single slow command or save could block
unrelated authenticated readers even after their TLS handshake completed.

A loopback mTLS regression enrolls 32 identities, stalls either WG apply or
registry persistence, and issues 32 fleet requests with the existing 1-second
budget. Before the change all 32 readers failed in each case. After the change
all readers finish while the writer is still deliberately blocked and see only
the previous committed state. Once the writer completes they see its new state.

A kernel control experiment runs **unchanged production source from `be51dbf`**
with the new test/diagnostic harness. In a disposable network-isolated container,
32 nodes have real WG handshakes, real mTLS, and ongoing UDP/TCP traffic. A
controller-only PATH wrapper delays exactly one `wg showconf` by two seconds.
This delay is below the existing 5-second command timeout. It does not change
kernel peers or application routes. The slow-reconcile phase is a strict planned
phase: HTTPS retains 1 second, application UDP/TCP 500ms, with no allowed losses
or reconnects. The fixed code runs the same experiment and CPU quota.

The first 2-CPU control recorded 41 HTTPS deadline failures. All completed TLS
and request transmission before waiting for a response. It also exposed one
explicit graceful-shutdown 503 crossing a phase boundary; that separate harness
classification defect was repaired, then the control repeated. Failed runs are
retained, never reported as successful validation.

Final local results (Go 1.25, Linux kernel WireGuard, 2026-09-17):

| Production source / mode | Nodes | Planned probes | Planned failures / reconnects |
| --- | --- | ---: | --- |
| `be51dbf`, same new harness, 2 CPU quota, no race | 32 | 103,647 | 42 HTTPS deadlines / 0 |
| Fixed, 2 CPU quota, no race | 32 | 104,401 | 0 / 0 |
| Fixed, race enabled, no CPU quota | 1 / 3 / 8 / 32 | 145,225 total | 0 / 0 |

In the repeated control all 32 nodes experienced deadline failures. All 42 failed
requests completed TLS (handshake duration at most 2.76ms) and wrote their request;
41 received no response byte before expiration. Resource samples bracketing two
seconds of the slow phase recorded zero CPU throttling in the control. This
supports response-side blocking rather than TLS or quota exhaustion **in this
injected experiment**. The fixed run's 992 HTTPS slow-phase probes all succeeded,
with observed p99 5.66ms and maximum 7.62ms; these are run-specific measurements,
not a production latency guarantee. Failed requests are counted separately and
are not excluded to create a successful percentile.

Both 2-CPU runs captured the quota (`200000 100000`), GOMAXPROCS=2, non-race build
and every requested cgroup field. Positive packet-loss controls detected 100 UDP
failures per fleet size; application UDP/TCP stayed successful through planned
PKI transitions and both controller restart modes. Intentional network-loss and
node/controller restart windows are evaluated separately from planned phases.
CI links and subsequent runs are recorded on the PR and issue #39.

This proves a causal failure path and the effect of the fix. It does **not**
prove that an injected two-second command delay was the unique cause of the
unprofiled historical Actions failure.

## Implementation and invariants

A mutation mutex serializes **every registry writer**: registration, NAT reports
and node removal. The registry mutex protects construction/publication of
committed snapshots and direct-readiness state. External command execution,
fsync and rollback temporarily release only the registry mutex. It is reacquired
on both normal and panic paths before the caller resumes. A failed transaction
still leaves the published registry unchanged, and rollback retains its own
execution budget. Successful reads during a mutation report the last committed
state, not the current intermediate kernel configuration.

Node removal, revocation, CA activation/retirement/rollback and backup retain their exclusive
admission barrier. Requests admitted before those operations still drain before
revocation/removal becomes authoritative. Read-only `pki.status` uses shared
admission so a status poll does not introduce a global writer barrier behind a
slow request. Fleet response serialization occurs after releasing the registry
mutex; a slow network client cannot hold up registry access. Heartbeat time is
assigned after entering the serialized writer section.

This is not a lock-free controller. Slow mutations still queue other mutations,
and destructive/admin transitions intentionally wait for admitted requests.
Filesystem or CPU starvation can still violate latency objectives. The change
preserves startup reconciliation, heartbeat WG drift repair, authenticated
resource binding, durable storage semantics and shutdown ownership guarantees.
It does not cache away WG reconciliation or weaken authorization to improve a
benchmark.

## Diagnostics and artifacts

`vpnctl_controller_stage_seconds{operation,stage}` uses fixed route/operation and
stage names, never node IDs or arbitrary request paths. It records handler time,
admission wait, identity/fleet registry wait, certificate authorization, writer
wait, apply, persistence and rollback. Existing command histograms distinguish
ip/wg/other with success/error/canceled/timeout. Histograms are aggregate signals;
their percentiles cannot be added to derive a per-request trace.

Each HTTPS probe records elapsed milestones from its own start: transport
entry, TCP connect, TLS start/completion, connection acquisition, request write,
and first response byte. Missing milestones remain absent, including on timeout.
Attempt count and connection reuse are explicit. Credential reload precedes
transport entry; time before that milestone must not be called server latency.
Trace callbacks synchronize access because they can arrive from transport
worker goroutines after cancellation.

Each node-size artifact directory contains:

- `node-*.jsonl`: application results and HTTP milestones, with start/end phases.
- `telemetry.jsonl`: once-per-second allowlisted command/controller/Go/process
  metrics, or an explicit scrape failure (expected during controller restart).
- `resources.jsonl`: timestamped phase, Go/build mode, CPU count/GOMAXPROCS and
  cgroup-v2 quota, CPU usage/throttling/pressure, memory and IO pressure. Missing
  files are explicitly listed. Counters require deltas; CPU throttled time is
  not itself a measured HTTP request delay.
- Existing `summary.json` and `kernel.json` retain loss/reconnect and WG evidence.

Resource sampling runs in the test coordinator's mount namespace because
`ip netns exec` remounts /sys and can hide the original cgroup mount. HTTP scraping
runs in the controller network namespace. Both use UTC and identical phase
markers. The artifact filter exports only diagnostic metric families; it omits
credentials, environment variables, command lines and unrelated node labels.

An HTTPS request starting before intentional shutdown may receive the gate's
explicit `503 Service Unavailable: controller shutting down` after that phase
changes. This exact rejection, like EOF/reset, is attributed to the recorded
restart window. Generic 503/auth errors, deadlines, and UDP/TCP failures retain
their original strict checks; no samples are discarded.

## Reproduction and verification

```sh
go test -race ./...
go test -race ./internal/controller -run 'Test(FleetReads|SerializedRegistry|SlowFleet|RegistryIOPanic|AdditivePKI|CAActivation)' -count=5 -timeout=90s
go test -race -tags=integration ./tests/integration -run 'Test(Trace|Telemetry|NetworkAccounting)' -count=5
go vet ./...
go vet -tags=integration ./tests/integration
./scripts/test-netns.sh
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_NETNS_SIZES=32 ./scripts/test-netns.sh -test.run=TestNetns_PKILifecycleUplink
```

The before/after control uses the same new integration harness over archived
`be51dbf` versus the fixed production source. It never substitutes a different
request deadline or drops failing observations. The normal 1/3/8/32 matrix
retains renewal, revocation/replay, activation, rollback, retirement, graceful
and forced restart, cold node recovery, partial-command timeout rollback, and
packet-loss positive controls. Additional regressions cover mixed concurrent
registration/NAT updates with unique leases, slow HTTP writers, and restoration
of the registry lock after injected writer panic.

No raw credential, temporary runtime registry, or user configuration is committed.
The verified size/load envelope and any further CI failures belong to #39;
one passing run is not a universal latency or production capacity guarantee.

## Rejected CA commands and admission draining (#51)

The first external-uplink CI for PR #50
([35183232152](https://github.com/timo-kang/vpnctl/actions/runs/35183232152)) failed
68 HTTPS requests in the 32-node rotation phase. All 68 completed TLS and wrote
their request, with no first response byte. Controller telemetry showed admission
wait dominating the fleet-handler delay. CPU/IO pressure was present; CPU quota
throttling was zero. Application UDP/TCP and all new relay fault checks passed.
This run remains a failure, and triggered reopening the M1 gate.

`adminPKI` requested the exclusive admission lock even for duplicate prepare or
activate/retire attempts whose prerequisites were not met. A waiting RWMutex
writer blocks new readers while previously admitted registry work drains. The
regression holds a registry save and repeatedly issues an impossible prepare:
before the fix all 32 authenticated fleet reads exceed one second; after the fix
all reads finish while the save remains blocked. The rejected operations finish
without requiring that admitted mutation to drain.

CA commands now perform a read-only preflight. Activation/retirement/rollback still acquire
exclusive admission, recollect confirmed identities and repeat every check under
the authority write lock. A successful preflight cannot authorize a later state:
tests cover revocation after preflight, duplicate prepare, minimum overlap and a
new confirmed node arriving while the administrator waits for admission. The fix
does not relax request deadlines, trust/ack gates, revocation ordering or storage
semantics. It does not identify every cause of the older unprofiled 287 failures.


## PKI committed reads and additive prepare (#58)

The previous registry fix did not isolate authority reads: every TLS config load,
status/snapshot, and certificate authorization took the same authority mutex as
issuance, trust acknowledgement, CA updates and their durable file writes. An
injected blocked write reproduced a one-second deadline failure before this fix.
This identifies a causal bottleneck; it does not establish the unique cause of
all seven HTTPS timeouts in historical Actions run `35299442539`.

Authority writers now serialize and mutate deep clones, publishing one immutable
snapshot only after successful replacement. If replacement succeeds but a later
write step reports an error, the existing exact-byte disk check still publishes
the visible state while returning the error. Thus a committed revocation cannot
be forgotten in memory. TLS configuration, status, snapshots, CA preflight and
known-certificate authorization read the last published generation. Caller-owned
TLS objects and status maps cannot mutate the stored snapshot. Legacy first-use
metadata still takes the writer lock, revalidates current trust, and commits once
before authorizing; it is intentionally outside the nonblocking known-reader path.

CA prepare only adds a pending trusted root and retains the active signer. It now
uses shared controller admission. Activation, retirement, rollback, revocation,
removal and backup keep exclusive admission. Activation recollects confirmed node
identities after draining requests and repeats acknowledgement checks. A request
admitted concurrently with prepare may receive the previous generation and must
refresh/retry its acknowledgement, as for any generation conflict.

The controller request barrier remains essential: a raw Authority read that overlaps
a write can linearize before that write. Protected controller requests drain before
a destructive operation and check the newly published state on subsequent admission.
No guarantee is made that destructive operations on arbitrarily stalled storage meet
a one-second request objective. They deliberately prevent stale authorization.

`vpnctl_pki_authority_seconds{stage}` separates `writer_wait`, `writer_hold`, `persist`,
`tls_snapshot`, `authorize`, and `status`. Controller stage metrics additionally
record `pki_transition/admission_wait` and `pki_transition/exclusive_hold` for the
security barrier. These fixed labels contain no identity or credential material.
The integration telemetry allowlist includes the histogram bucket/sum/count families.
Histograms aggregate overlapping work; do not add their percentiles as a request trace.

Regression coverage deliberately holds prepare, issuance, renewal, acknowledgement,
server renewal and revocation writes while 32 readers inspect the previous snapshot.
Actual TLS handshakes and authorization also run with 1/3/8/32 simultaneous clients
while a write is held. Other checks cover legacy first-use contention, detached return
values, rejection after revocation/retirement, pre-replacement ENOSPC, post-replacement
EIO, and a new identity arriving after activation preflight. Request deadlines remain
one second. Full race tests, repeated fault tests, vet and integration diagnostics pass.

```sh
go test -race ./...
go test -race ./internal/pki -run 'Test(CommittedReads|TLSAndAuthorization|LegacyFirstUse|PublishedAuthority|AuthorityFailures|AuthorityPostRename)' -count=5
go test -race -tags=integration ./tests/integration -run 'Test(Trace|Telemetry|NetworkAccounting)' -count=3
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=1 ./scripts/test-netns.sh -test.run '^TestNetns_PKILifecycleUplink$'
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 ./scripts/test-netns.sh -test.run '^TestNetns_PKILifecycleUplink$'
```

CPU-quota network measurements are recorded below; CI evidence is linked on #58.
Admin overload admission and result ambiguity remain tracked independently in #60.


### Verified sandbox resource envelope (2026-09-18)

The quota includes controller, every agent, traffic worker and harness, all sharing
one Docker cgroup. It is not the CPU allocation of an isolated production controller.
All builds below are non-race, Go 1.25, Linux kernel WireGuard. Application budgets
remain HTTPS 1s and UDP/TCP 500ms, with zero planned-phase loss/reconnects allowed.

| Entire sandbox quota | Fleet | Planned probes | Failures / reconnects | HTTPS p95 / p99 / max |
|---|---|---:|---|---|
| 1 CPU | 1 / 3 / 8 | 38,179 total | 0 / 0 | per-size p99 9.59 / 6.38 / 5.83ms |
| 1 CPU | 32, two attempts | startup incomplete | failed; no passing lifecycle verdict | responder readiness exceeded 5s |
| 2 CPUs | 1 / 3 / 8 / 32 | 138,966 total | 0 / 0 | 32-node: 7.19 / 9.79 / 46.85ms |
| 2 CPUs | 32, repeat 1 | 99,558 | 0 / 0 | 10.44 / 14.68 / 60.31ms |
| 2 CPUs | 32, repeat 2 | 102,057 | 0 / 0 | 7.12 / 10.26 / 66.23ms |

The three successful 32-node runs contain 12,576 / 12,455 / 12,769 HTTPS successes
and zero planned HTTPS failures. Intentional packet-loss controls detect 100 / 100 /
101 UDP failures. Relay forwarding, return route, firewall, uplink and NAT fault
cycles also pass. This remains single controller/relay validation, not multi-relay
or physical communication-network switching (M3).

The first 1-CPU startup failure recorded approximately 27.22 CPU-seconds consumed
across 28 seconds, 256 additional throttled periods out of 280, and 128.66 seconds
of aggregate throttled-task time. Aggregate throttled time is not request latency.
In the repeat, the final starting agent log is empty while earlier agents/controller
continue running. The observations establish an insufficient whole-sandbox startup
profile, not a universal minimum CPU requirement for production. The failed runs
are retained; no startup or request deadline was raised to claim success.

This failure also exposed late registration of the sanitized-log cleanup. It now
registers before starting the first process, preserving logs on early initialization
failure. Private keys and runtime credential files remain excluded from artifacts.
[PR #61](https://github.com/timo-kang/vpnctl/pull/61) records the exact evidence and
[its passing CI](https://github.com/timo-kang/vpnctl/actions/runs/35309665582).
