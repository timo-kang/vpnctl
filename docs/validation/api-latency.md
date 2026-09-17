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

Node removal, revocation, CA transitions and backup retain their exclusive
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
go test -race ./internal/controller -run 'Test(FleetReads|SerializedRegistry|SlowFleet|RegistryIOPanic|ReadOnlyPKI)' -count=5 -timeout=90s
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
