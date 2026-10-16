# Experimental process and Go runtime cost attribution

This follows the maintenance/child accounting in #251. It collects evidence for
why an observation can be acquired before the previous observation expires but
published after expiry. It does not change ownership, approval, lease, freshness,
command budgets, policy, application behavior, or any original failure verdict.

Questions:

1. How much actual CPU does the parent process use over a completed cycle,
   separately from reaped external children?
2. Are completed GC cycles, estimated GC CPU, GC pauses or runnable latency
   substantial enough to justify a narrower trace/intervention?
3. Does enabling this sampling itself change the outcome or cycle cost?

`VPNCTL_RUNTIME_COSTS=1` adds `diagnostics.runtime_cost` when a recorder starts.
All other values omit it and avoid usage/metrics reads. This is independent of
`VPNCTL_COST_DETAILS`. VM capacity scenarios expose `--runtime-costs`; the typed
request defaults off and the guest explicitly sets the worker environment to
`0` or `1`, overriding inherited values. Both selectors and their supervisor
inherit the mode. The request shape of default control runs is unchanged.

## Measurement contract

- `scope=process`: every goroutine and OS thread in that Go process is included.
  Concurrent recorders overlap and MUST NOT be summed as independent work.
- `process_cpu` is the delta of Linux `getrusage(RUSAGE_SELF)` user/system CPU.
  It excludes external children, whose CPU is separately in `details.commands`.
  This is actual OS accounting, not a runtime CPU-class estimate.
- `start` and `finish` each have separate `process_cpu` and `metrics` read bounds
  in CLOCK_MONOTONIC. These are not an atomic snapshot across sources. Metric
  bounds include allocation/read/copy; CPU bounds bracket the syscall. Readers
  must account for the interval uncertainty rather than align point events.
- Baselines are immutable per recorder. Histogram counts AND boundaries are
  copied from runtime-owned memory. Snapshots return independent values.
- Sampling and serialization have overhead. It is not subtracted from elapsed
  time or explained away; the same-binary off/on controls measure its effect.
  CPU read intervals do not cover all setup/final serialization work, so their
  delta is not an exact CPU accounting of the entire serialized cycle.
- `available=false` omits the value. Missing metrics, wrong kinds, reset/decreased
  counters, invalid bounds, nonfinite counters or malformed histograms are never
  converted to zero. An available zero remains explicit.

The fixed, bounded metric set is:

| Metric | Interpretation and limit |
| --- | --- |
| `/cpu/classes/gc/total:cpu-seconds` | Estimated GC CPU, including idle GC work |
| `/cpu/classes/user:cpu-seconds` | Estimated Go user CPU, with some runtime work |
| `/cpu/classes/total:cpu-seconds` | Estimated available CPU capacity, including idle time |
| `/gc/cycles/total:gc-cycles` | Completed GC cycles; does not locate pause times |
| `/gc/heap/allocs:bytes` | Cumulative Go heap allocations; not RSS or race detector memory |
| `/sched/latencies:seconds` | Sampled runnable-to-running latency; not OS scheduling trace |
| `/sched/pauses/total/gc:seconds` | Completed GC stop-the-world pause distribution |
| `/sync/mutex/wait/total:seconds` | Cumulative Go/runtime mutex contention, not the ownership FIFO/flock |

Go CPU classes are estimates/overestimates, comparable ONLY with other
`/cpu/classes` metrics. Do not divide or subtract them against OS/cgroup/child
CPU, or use total capacity as active CPU. Updates need not be instantaneous at
cycle boundaries. A zero delta does not prove absence of runtime work.

Histogram output contains event count and the bounds of the highest bucket with
new events. Its lower bound is inclusive, upper bound exclusive. Infinity is an
explicit `max_*_unbounded` flag with that bound absent, never invalid JSON. Zero
events have no maximum. Full buckets are not serialized; no percentiles or exact
maximum/pause timeline can be reconstructed from this summary. Sampled events
may span a boundary. These observations alone cannot attribute a particular
publication failure to GC or scheduler delay.

Authoritative semantics: [Go runtime/metrics](https://pkg.go.dev/runtime/metrics@go1.25.0)
and [Linux getrusage](https://man7.org/linux/man-pages/man2/getrusage.2.html).
No arguments, addresses, paths, credentials, stacks or process environment are
recorded by this instrumentation.

## Remote experiment and interpretation

Use one fixed source and immutable images per ordinary/race build, detailed
command accounting ON in every case, and runtime sampling OFF/ON in a
predeclared eight-case forward/reverse schedule. Keep original eight-path,
two-selector, CPU quota, deadlines and original validators unchanged. Record
source/image/compiler/CPU identities; prior runs with different kernels/CPUs are
not matched controls. No retries, cancellations or local privileged tests.

First analyze original frozen receive windows. If a failure contains no new
completed cycle there, report that comparison unavailable. Separately compare
the first app2 cycle completed after its frozen baseline at each healthy
position, labeled as a diagnostic interval (including post-failure cleanup when
applicable). This rule is fixed before execution. Later data must never repair
an original failure. Include missing cycles/samples, failed starts, unchanged
baseline age, publication receipt gaps and all original verdicts.

Report per-process OS CPU, separately measured child CPU/wall, fixed runtime
counters and sampling durations with their actual time coverage. Do not turn
wall minus CPU into a scheduler/GC estimate. Keep FIFO/ownership timing as
separate evidence. Two repetitions provide descriptive checks, not a population
estimate or a language-selection result. A Rust comparison remains conditional
on evidence of a Go-specific bottleneck.
