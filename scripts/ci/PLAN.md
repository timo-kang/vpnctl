# Actual selector CPU and allocation stacks

Experiment-only runner; never merge this workflow into main. The exact source
is pinned in `uplink_handoff.py` and `plan.json`. It extends runtime diagnostic
source b58417a, with no product gate change.

The previous run 38929477620 naturally completed all eight invocations: four
ordinary passes and four race failures. Runtime counters made a long GC stop
less plausible but did not identify the function causing extra parent CPU or
allocations. Parent CPU, child CPU, admission wait and total elapsed time are
different quantities. This experiment records actual app2 Go stacks.

## Fixed schedule and build

| Order | Race build | Selector profiling | Child details | Runtime counters |
| --- | --- | --- | --- | --- |
| 1 | on | off | on | on |
| 2 | off | off | on | on |
| 3 | off | on | on | on |
| 4 | on | on | on | on |
| 5 | on | on | on | on |
| 6 | off | on | on | on |
| 7 | off | off | on | on |
| 8 | on | off | on | on |

All cases use the original steady eight-path capacity fixture and validator,
API load OFF, two Go selectors, split two guest/outer CPUs: robot supervisor and
selectors share 0.5 CPU on CPU 0; controller, relays and measurement have 1 CPU
on CPU 1. Container 2 GiB/no swap/network none/capabilities none, guest 768 MiB.
Original preparation placement, limits, lease/freshness/ownership and payload
checks are unchanged. This is not a Go-versus-Python app trial.

Compile the diagnostic `vpnctl_profile` tag in the CLI for BOTH runtime OFF/ON
cells; other Go producers must not have the tag. Verify actual executable build
metadata, source revision and hashes. Build each race mode once, reusing the same
immutable Docker base and kernel/initrd/Python bytes; reuse that exact per-mode
image for every cell. No rebuild after failed initial preparation. The only
active compiler difference across the pair is `-race`.

Local binary review caught Go 1.25 stamping an enclosing checkout's revision
for a nested linked worktree (.git file), rather than the actual source commit.
Use an independent local clone with a real .git directory, check out the exact
source and require a clean checkout. The tagged CLI must embed the exact SOURCE
revision with vcs.modified=false; otherwise no image is admitted. Retain the
actual compiled build info, not a caller-supplied revision label.

## Sampling protocol fixed before execution

The initial private draft proposed profiling at process startup. Before remote
execution, review found startup may precede two-selector contention. The final
protocol instead arms at startup and triggers once after the original two
publication baselines. Both fixture trigger and producer collection clocks are
recorded. This change is pre-experiment, not a response to measured outcomes.

Only app2 receives the private profile directory. The guest resets inherited
flags and accepts only a strict boolean for this exact case. The hook requires
VM worker identity and the exact app2 target-reconcile watch command. Profiling
is absent from normal product builds. No HTTP profiler or kernel changes.

After a private zero-byte trigger (100 ms polling, two-minute wait ceiling),
write sampled cumulative allocation stacks, start default Go CPU profiling,
wait eight seconds, stop/drain CPU output and write a second allocation profile.
Actual CLOCK_MONOTONIC brackets, PID, source/runtime/sample-rate identities,
file hashes/sizes and complete/truncated/error state accompany each profile.
Three profiles are capped at 256 KiB each; two metadata files at 16 KiB for
transport. The optional reader accepts five fixed names and at most three
fixtures; symlinks, nonregular files and over-limit content are unavailable.
No profile may erase a worker's original failure, stop another profiler, extend
qualification, cancel the process or tune GC/scheduler/limits.

Collection can overlap partial cycles or failure cleanup. An early process exit
can leave missing final metadata: that is unavailable, not a complete zero-cost
sample. Allocation profiles retain default sampling and can lag two GC cycles;
there is no forced GC. Difference profiles are not exact interval allocation or
RSS measurements and include the profiler's own allocations. CPU profiles omit
children and waiting time; C/race-detector/syscall frames may be unattributed.

## Predeclared analysis and acceptance

1. Verify source/runner/plan and all build/image/role/CPU/flag identities. Retain
   all eight outcomes and replay original frozen verdicts with original Go code.
2. Verify profile manifest identity, exact files, sizes/hashes, monotonic brackets
   and completeness. Match producer PID to fixture. OFF has no producer profile.
   Preserve unavailable/partial profiles as such, never as zero.
3. Match profile clock coverage to the frozen qualification and later cleanup;
   do not attribute cleanup samples solely to the earlier failed window. Require
   at least 50 CPU samples for a hot-path ranking. A smaller sample is insufficient;
   do not lengthen the window or rerun after observing that result.
4. Compare existing completed-cycle evidence inside original frozen windows by
   healthy_index/role. Separately label the first app2 post-baseline cycle and
   any diagnostic cleanup. Compare profile OFF/ON within each build to expose
   instrumentation effects before interpreting race/plain differences.
5. Use adequate stacks to propose one causally testable hot-path intervention.
   Two repetitions are descriptive, not hardware SLO, failure-rate, equivalence,
   Go-language or Rust-rewrite evidence. Do not waive old PR-head gates.

Every invocation runs once in this order; preserve original nonzero exits and
continue remaining planned cases. No cancellation, retry, reordering or green
selection. Existing 35m initial/25m subsequent watchdogs and 285m execution/310m
job ceilings remain; they are not app recovery targets. Raw profiles, logs and
unadopted measurements stay in the encrypted artifact with the existing public
recipient. No host networking/kernel/clock/power/SIGSTOP actions locally.
