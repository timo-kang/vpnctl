# Controller and command lifecycle reliability

Scope: M1 issue #38, based on main `4dcb615` (PR #40). This work does not
complete M1 #13 or establish the cause of the earlier 32-node HTTPS deadline
failures tracked in #39. VPN carries robot-to-server uplink traffic; these
changes do not issue robot behavior commands or implement multirelay selection.

## Reproduced defects and self-review

- A missing executable produced an empty error because Output discarded the
  execution error and returned only its output. The regression now checks the
  original `exec.ErrNotFound`, nonzero exit status, and separate stdout/stderr.
- Controller HTTP startup failure left its already-started UDP responder bound.
  The regression failed with address-in-use before lifecycle cleanup was added.
- Unbounded ip/wg processes could prevent discovery, mutation and shutdown from
  completing. Killing only the command leader could leave descendant processes
  holding pipes. A further review reproduced a failed leader masking
  `ErrWaitDelay` with `ExitError`, leaving its child alive. Cleanup now covers
  every failed command as well as context cancellation.
- The former shutdown API neither connected controller lifetime to SIGTERM /
  SIGINT nor coordinated public API, admin IPC, maintenance and UDP cleanup.
  Closing connections alone does not prove that a handler has finished saving.
- Standalone STUN set its timeout only after DNS/dial and used a separate callback
  goroutine without end-to-end cancellation coverage. DNS, socket I/O, retransmission and cancellation now share the
  supplied per-server budget, with owner cancellation stopping the sweep.

## Contracts and limits

Production commands use a 5-second default timeout, a separate process group,
context cancellation, and a 250ms pipe-drain bound. OSRunner.Timeout can override
this in code; there is no new user configuration setting. WG mutations have a
30-second total budget in addition to per-command limits. Cancellation errors
from interface/showconf reads are propagated instead of triggering speculative
writes. Peer discovery, agent apply and CLI up/down/status/doctor pass their
owner context through. Legacy test runners remain injectable.

Controller startup reconciliation uses its owner context. Accepted registry
mutations use their own budget, independent of a disconnected HTTP client or
controller shutdown. A failed apply obtains a **fresh** rollback budget, keeping
memory and the persisted registry unchanged unless the transaction succeeds.
If rollback also fails, both errors remain visible and startup reconciles WG
from the durable registry. This is not atomic kernel configuration: traffic can
observe the interval between partial application and rollback.

Shutdown closes admission and listening sockets for both HTTP and admin IPC,
then drains accepted handlers. After 10 seconds, remaining client connections
are closed. The owner still waits for handlers that may write or rollback;
only afterward do maintenance, UDP and state ownership end. Startup failures
close all resources started so far. Independent WireGuard interfaces and
application UDP/TCP sessions remain in place across controller restarts.

The 10-second grace is **not** a maximum process lifetime. Many already-admitted
mutations may queue; filesystem stalls and uninterruptible kernel I/O cannot
be made safe by releasing the lock early. A descendant that deliberately escapes
its process group is outside the ip/wg command-runner contract. A sequential
STUN sweep still scales with the configured server count; a nonpositive timeout
requires an owner deadline/cancellation for bounded DNS. These limits must not
be advertised as a complete M1 latency guarantee.

`vpnctl_system_command_seconds{command,result}` records duration and outcome.
Command labels are restricted to ip/wg/other and results to
success/error/canceled/timeout. Slow/failed command logs omit arguments and
output; returned errors preserve stderr and original causes, never stdout
(which may contain a private WireGuard key). This metric is a diagnostic signal,
not proof of the CI request-latency root cause.

## Verification

```sh
go test -race ./...
go test -race ./internal/execx -count=5 -timeout=60s
go test -race ./internal/controller ./cmd/vpnctl -run 'Test.*(StartupFailure|Shutdown|CommandTimeout|Signals|ClientCancellation)' -count=5 -timeout=90s
go test -race ./internal/stunutil ./internal/peersource ./internal/wireguard -count=5 -timeout=60s
go vet ./...
go vet -tags=integration ./tests/integration
go build -o /tmp/vpnctl-check ./cmd/vpnctl
./scripts/test-netns.sh
```

Regression coverage includes real subprocess timeout, owner cancellation,
already-canceled commands, inherited pipes with both successful/failed leaders,
repeated HTTP/admin startup failure, two listeners draining together, 200 rejected
requests after admission closes, slow header/body clients, and ownership retained beyond the grace while
accepted writes finish. Client cancellation during WG apply must still commit
consistent kernel-model/memory/disk state. CLI subprocess tests restart the same
state directory after SIGTERM, SIGINT and SIGTERM again. STUN tests cover blocked
DNS, canceled sweeps, dropped first request with retransmission, and repeated
silent-server timeouts. All network unit tests use loopback; WG is faked there.

The kernel test runs exclusively in the disposable `--network none` Docker
container. A temporary PATH-local wg wrapper performs **real syncconf**, then
hangs once. The test verifies the partially updated peer set, unchanged durable
registry, and rejected second owner during SIGTERM. After the real 5-second
command timeout it checks rollback in the kernel, process exit, lock reuse,
restart and successful next registration. No host wg binary or host network
configuration is replaced.

The existing 1/3/8/32-node matrix also checks graceful SIGTERM and forced
controller restart, with zero UDP/TCP failures or reconnections during either
restart. It retains renewal, revocation/replay, CA activation/rollback/retirement,
node cold restart, and a positive control with deliberate packet loss. HTTPS
continues to have a 1-second request budget; application probes retain 500ms.
Run-specific results are recorded below/on the PR; failed runs are not successes.

## Restart-boundary measurement defect

Merged-main [run 35165430156](https://github.com/timo-kang/vpnctl/actions/runs/35165430156)
passed 1/3/8 nodes but reported 9 HTTPS EOFs among 106,098 planned 32-node samples.
All nine began at 00:13:52.973–.993 UTC; their 111–134ms durations overlap the
intentional controller-stop phase recorded at 00:13:52.994. Requests recorded
only their start phase, so intentional termination was charged to CA rollback.
This evidence supports a phase-boundary classification defect, not an HTTPS
latency fix or a retrospective claim that the failed run passed.

Raw events now retain start and end phases. Only HTTPS EOF/connection-reset
samples that end in an intentional controller-restart window are charged to that
window. No samples are dropped. Same-phase EOFs, deadline/authentication errors,
and every UDP/TCP failure retain the original strict checks. A table-driven test
checks these exclusions. This change does not explain the distinct 287 HTTPS
1-second deadline failures in run 34946555633; #39 remains open.

## Operator procedure

1. Request ordinary controller shutdown with SIGTERM (SIGINT is also supported).
   Stop new administrative work and wait for process exit. Keep the configured
   data directory and its ownership lock in place; never delete the lock file
   to admit a second writer. Connections may close after the 10-second grace
   while a mutation continues to drain.
2. If shutdown waits, inspect the controller shutdown warning, command outcome
   logs/metrics and storage health. Allow admitted apply/rollback work to finish.
   Repeated SIGTERM does not release ownership. A supervisor stop timeout must
   account for queued mutations; 10 seconds is not a guaranteed safe kill point.
3. If an operator must force-stop an irrecoverably stuck process, stop/reap its
   entire service cgroup/process tree before restarting. Killing only the
   controller can orphan ip/wg children. Treat an interrupted request as having
   an unknown outcome until registry and WG are inspected.
4. Restart with the same data directory and `wg_apply: true`. Startup obtains
   exclusive ownership and reconciles the kernel from the durable registry
   before serving requests. Check registry identity/IP leases, current WG peers,
   handshake/traffic recovery and PKI status. Retry registration only after
   confirming that the new controller owns state and reconciliation succeeded.
5. If durable state itself is damaged, stop the service and follow the existing
   PKI/registry backup-and-restore procedure in [the PKI runbook](../pki-lifecycle.md#일관된-backup과-restore). Do not replace
   registry or certificate files while a draining owner may still write them.
