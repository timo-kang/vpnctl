# Parent process and Go runtime attribution

Experiment-only workflow, never merge into main. Fixed source: `b58417a5da98c103cacce88af060c80b6c1142ff`.
The previous maintenance source b53147e and runner7857fc9 remain immutable. Run
38923169391 finished4PASS/4FAIL: all four race cells failed app2 freshness, all
four ordinary cells passed, regardless of child-detail accounting. This is a
within-run descriptive result. Earlier run38915036336 had different guest CPU
and kernel bytes, so between-run changes do not isolate a source effect.

All12 race sampled failures retained an unchanged baseline; some baselines were
already expired at window start. In diagnostic cleanup rows, every next
observation was acquired before prior expiry but published after. Admission
queue and maintenance lease/nft elapsed time dominate; wall minus child CPU
cannot establish a Go/GC/scheduler cause. Original publication receipt gaps
remain inconclusive, never relabeled as packet loss or fixed by cleanup.

## Fixed schedule

Eight original eight-path capacity invocations, original validator, API load OFF.
Child-detail accounting ON in every invocation. Runtime sampling OFF/ON, two
repetitions per cell, reversed second block:

| Order | Go race build | Child details | Runtime sampling |
| --- | --- | --- | --- |
| 1 | on | on | off |
| 2 | off | on | off |
| 3 | off | on | on |
| 4 | on | on | on |
| 5 | on | on | on |
| 6 | off | on | on |
| 7 | off | on | off |
| 8 | on | on | off |

All use split two outer/guest CPUs, robot supervisor and both Go selectors share
0.5CPU on CPU0, controller/relays/measurement1CPU on CPU1. Container2GiB/no swap,
network none/capabilities none, guest768MiB; preparation placement unchanged.
This is not a Go-versus-Python application trial. No new app stall or API fault.
No approval/lease/ownership/freshness/deadline/qualification changes. Existing
race safety and PR-head qualification gates remain required.

## Build, sampling and preservation controls

Build each race mode once at first appearance. Ordinary mode reuses the exact
Docker base image ID. Verify actual active executable race/compiler metadata,
same within-run kernel/initrd/Python and unchanged per-mode images. Historical
migration binaries are retained but unused; their build paths may differ.

Runtime off/on use the SAME image/binary for each build mode. Both instrumentation
flags cross the VM boundary as booleans and override inherited worker flags.
Record invocation and runner/full-verdict modes. Offline verify actual runtime
field presence/absence in every retained selector/supervisor row, not just flags.

RUSAGE_SELF CPU excludes children and spans all process threads/goroutines.
Sampling intervals for CPU and Go counters are independently bracketed in
CLOCK_MONOTONIC; they are not atomic or exact full-cycle CPU coverage. Go CPU
classes are estimates comparable only within their family, not to OS/cgroup CPU.
GC/latency histogram summaries are event counts and largest-bucket bounds, not
exact pauses/timelines/percentiles. Mutex counters are not ownership FIFO/flock.
Zero differs from unavailable; missing/reset/malformed samples cannot become
zero. Overlapping process-wide intervals cannot be summed. Sampling/serialization
overhead is retained and checked against disabled controls, not subtracted.

Every failure preserves original exit and verdict. Remaining predeclared trials
continue; no retries, cancellation, reordering or selective rebuild for green.
If preparation fails, record infrastructure failure rather than rebuild. Keep
all raw artifacts encrypted with the existing off-runner private key recipient.
Public records contain protocols, completion counts, failure classes and limits.

## Predeclared analysis

1. Validate source/runner/plan hashes, actual build/image/CPU identities, roles,
   resource quotas, detail command counts and original validators. Replay all
   original frozen publication/freshness verdicts without launching networking.
2. Compare completed records RECEIVED within the original frozen windows, matched
   by healthy_index and role. Zero completed rows means unavailable comparison.
   Supervisor envelope is separately labeled, not a frozen receive window.
3. Independently, for each healthy_index choose the FIRST app2 completed cycle
   after its frozen baseline_count. Label its finish/receipt relation to the
   frozen window, retain missing cycles explicitly, and retain whether the
   report failed. Post-failure cleanup rows are diagnostic only and cannot repair
   qualification or be pooled with frozen performance observations.
4. For matched intervals report actual parent CPU, external child CPU/wall,
   runtime counter deltas, GC/latency event/max-bucket summaries, sampling spans,
   and original admission/maintenance/ownership boundaries. Do not infer GC or
   scheduling as the wall-minus-CPU remainder. Include unavailable samples and
   unchanged/stale baselines. Do not invent percentiles from histogram maxima.
5. Compare runtime-on/off within each build for instrumentation effect; compare
   race/plain with runtime-on for diagnostic differences. Two repetitions are
   descriptive, not failure-rate/hardware-capacity/equivalence/SLO estimates.
   A Go language claim or Rust comparison needs stronger evidence; traces remain
   a separate controlled intervention if temporal attribution is still needed.

Local preflight: Go race unit tests, integration compile, vet,110 VM Python tests
and15 runner tests. Wrong parent/child CPU source is caught by independent OS
usage bounds. No local VM, networking, kernel, clock, power or SIGSTOP actions.
Existing isolated cleanup and35m initial/25m later invocation watchdogs,
285m execution/310m job limits remain. Watchdogs are not app recovery targets.
