# Experimental maintenance cost attribution

This diagnostic branch follows #251. It does not change admission, authority,
lease, freshness, command deadlines, original verdicts, or the app protocol.
Detailed measurements remain in encrypted experiment evidence. This is not a
production logging configuration or a replacement for failing PR-head checks.

Questions:

1. While holding shared ownership, does maintenance spend time in approval/plan,
   per-entry eligibility, kernel checks, persistence, live authority checks,
   lease renewal/readback, or failure blocking?
2. Which fixed external-command family consumes that elapsed time?
3. How much OS child CPU is accounted for, and how often is usage unavailable?

`VPNCTL_COST_DETAILS=1` enables details on a newly started observation or
supervision recorder. Other values leave details absent. The VM runner exposes
`--cost-details` for capacity cases only and forwards a boolean to the guest;
control runs explicitly set the worker environment to `0`. Descendants inherit
it, including both selectors and the supervisor. No host network changes are
required to run the unit tests.

`diagnostics.phases` retains its original attribution. `diagnostics.details.steps`
records nonoverlapping maintenance substeps (the lease step can contain two grant
calls on a rearm). They are contained in the parent maintenance phase, and MUST
NOT be added to it. Unentered steps are absent, not measured zero-cost steps.
Context and cancellation propagate into every original backend operation.

`details.commands` groups external processes by phase/substep/executable family.
Only `ip`, `nft`, `wg`, `sysctl`, `cat`, and `other` are recorded; argv, arbitrary
paths, input, output, error strings and credentials are never retained. Counts
include failed attempts. `cpu_available` counts reaped ProcessState samples,
including failed exits and signals. `cpu_unavailable` counts missing samples,
including failed starts. Zero CPU with an available sample is different from a
missing sample. Fake Command calls without ProcessState are unavailable.

Wall time covers setup, execution, scheduling, I/O and wait. CPU is the OS
ProcessState user/system accounting for that child; on Linux it may include
waited-for descendants. It excludes the Go parent's CPU. Summed wall time can
exceed cycle time when commands overlap. Wall minus child CPU is not a Go-runtime
cost, a GC pause, or a specific scheduler/I/O wait. See the [Go ProcessState
contract](https://pkg.go.dev/os#ProcessState.UserTime).

Substeps and command counters use the same recorder mutex and snapshots copy all
maps. Opt-in adds clocks, contexts, maps, serialization and accounting overhead.
Compare instrumented and uninstrumented runs of the SAME build/image in a
predeclared order. Filter completed cycles using the original frozen receive
window and retain original failures, missing/truncated evidence and command CPU
availability. Do not substitute a later cleanup observation for a failed window.

This slice does not yet measure GC or Go runnable latency. If substantial parent
runtime cost remains plausible after command attribution, collect bounded
runtime/metrics or traces in a separate controlled experiment. Do not rewrite in
Rust based on elapsed-minus-child-CPU or on non-reproduction.
