# Maintenance and external-command cost attribution

Experiment-only workflow, never merge into main. Fixed source:
`b53147e9862601c308f79381c1e6807518639696`, based on the immutable previous source
`7af8b777a13a0acef5c685c6cbf817201a945b9e`. Previous run 38915036336 is final:
all ten planned build-comparison invocations passed; this did not resolve the
older natural failures or qualify existing failing PR heads.

Question: within the serialized ownership periods, which maintenance substep
and external-command family consume elapsed time? How much child CPU is actually
accounted for? Do NOT call wall-minus-child-CPU a Go runtime or scheduler cost.
This slice does not yet collect GC/runnable metrics or traces.

## Fixed schedule

Eight original eight-path capacity invocations, original validator, API load OFF.
Two repetitions of each cell, reversed second block. All use split two outer and
guest CPUs, robot supervisor and both selectors sharing 0.5 CPU on CPU0,
controller/relays/measurement one CPU on CPU1. Same initial-preparation placement,
container2GiB/no swap/network none/capabilities none, guest768MiB.

| Order | Go race build | Detail accounting |
| --- | --- | --- |
| 1 | on | off |
| 2 | off | off |
| 3 | off | on |
| 4 | on | on |
| 5 | on | on |
| 6 | off | on |
| 7 | off | off |
| 8 | on | off |

No new app stall, API outage, or full-app scenario in this focused experiment.
Original approval, lease, live ownership, freshness, deadlines, failures and
qualification functions are unchanged. Existing race CI gates remain required.
Both modes use the same new source; disabled details have no new clocks/maps/CPU
samples but still carry the common code changes, so this is not binary equality
with the prior source. Separate on/off controls measure the opt-in overhead.

## Build and evidence controls

Build each race mode once at its first invocation. The ordinary mode reuses the
race preparation's exact base Docker image ID. Verify same Go compiler and build
settings except race, same kernel/initrd/Python modules, expected actual build
metadata for all three active Go binaries, and unchanged per-mode image hashes.
Retain eleven binaries/modules; historical migration fixture hashes may differ
because of build paths and they are not run here.

Reuse each guest image for both detail modes, fresh guest overlays and fixtures
for every invocation. The guest receives a boolean and explicitly overrides
VPNCTL_COST_DETAILS to 0 or 1 for the worker and its descendants. Record the
requested mode in invocation.json, runner.json and the full verdict. Offline,
verify actual detail presence in both selectors and supervisor, command CPU
availability/count reconciliation and original frozen observation boundaries.
Requested flags alone are not proof the instrumented processes ran.

Every failure keeps its original process exit. Continue remaining planned cases;
never selectively retry, rebuild after preparation failure, or cancel for green.
Build overhead precedes the first two trials, so order/environment effects are
not eliminated. Same-run comparisons are descriptive; two repetitions do not
establish a failure rate, hardware capacity, equivalence or a deployment SLO.

Local preflight: relayobserve/relayapply/relayplan and CLI race unit suites,
integration compilation, go vet,107 VM Python tests and14 runner tests. New
command-evidence and runner schedule tests failed before implementation. Removing
ProcessState capture in a Go overlay makes the child-availability test fail.
No local VM/network/clock/kernel/power changes were made.

## Analysis and preservation

Keep original verdicts and immutable frozen input, including incomplete windows.
Use records RECEIVED inside those windows; match role and healthy_index, not
filesystem report order. Substep counters are nested within parent phases; do
not add them. Command durations can overlap; never sum them as exclusive cycle
wall time. Missing child usage is unavailable, not zero. ProcessState CPU excludes
Go parent work and on Linux may include children waited for by the command.

Compare on/off cycle, ownership and maintenance distributions for each build,
then instrumented substeps and child process counters. Evidence cannot distinguish
all parent scheduling, I/O, GC and quota effects yet. If unexplained parent cost
remains plausible, add separately controlled runtime metrics/traces. No Rust
rewrite is justified by this experiment alone.

Raw logs, counts, measurements and binaries stay encrypted. Publicly record only
protocol, completion counts, failure classes and causal limits. Existing safety
boundaries, isolated cleanup,35m initial/25m later invocation watchdogs and285m
execution/310m job bounds remain; these bounds are not recovery targets.
