# Same-image inventory decoding comparison (experiment only; do not merge)

Hypothesis: repeated JSON decoding during maintenance and observation ownership
checks adds enough CPU cost to delay the next successful observation on a quota
limited robot. Reusing decoding of byte-identical public inventories within one
sweep/wave may reduce that delay without extending evidence freshness or removing
any command, lease, approval, ownership or post-TCP check. A local parser benchmark
motivates this test; it does not establish an end-to-end improvement.

Baseline CLI source is latest main 6d07e08e109eae073d1ad11c5cf2edd8304b5148.
Its cmd/internal/go.mod/go.sum content matches the preceding 888b83b product.
Candidate source is a73c5aabf987023e63ccbfd1831094cb14085fd4, containing exactly
five reviewed relayapply files relative to baseline. Verify that complete diff
allowlist before compilation. Both CLIs use the same pinned Go 1.25.0 race builder.
The integration executable remains 02b32013ceaf0ad36e22216335767b7dc5604965;
its Go tests, thresholds, retries and instrumentation do not change. Controller
and guest harness have their own clean revision. No additional product or
integration changes are allowed in the comparison harness.

Build each CLI once in a separate clean Git clone, one integration executable,
and three compatibility executables. Build one runtime and one pristine guest
image containing all six binaries. Record actual compiler/race/VCS metadata
and every executable/image/kernel/initrd/runtime/tool hash. Verify identical
bundle bytes before each invocation. The only treatment is selection of the
baseline or candidate CLI via the test's existing VPNCTL_BIN mechanism. This
selects the whole product, including controller, relays and robot processes;
it is not a robot-only patch. Guest launch response records the fixed executable
path and hash used for the worker environment; the outer observer verifies it
against guest health and the shared image manifest. Arbitrary paths or other
profiles are rejected before launching the worker.

One CI job runs exactly four fresh VMs: baseline, candidate, candidate, baseline
(ABBA). Robot quota is 0.5 CPU in ALL FOUR runs. Fix 8 paths, two apps, removal
positions 0/3/7, split role placement (robot guest CPU 0; servers guest CPU 1),
server quota 1 CPU, outer quota 2 CPUs, and two guest vCPUs. Accounting is ON
with the same boot flags and bounded sampler in all four. Hold the same host CPU
pair, memory, image and runtime fixed. Fresh overlays and unique directories
prevent state reuse. No API load, added retries, workflow reruns, reordered cells,
or early stopping after product failure. Host-isolation or input-hash violation
stops later work and retains all partial evidence. Invocation watchdog 1200 seconds
is a test bound, not an application SLO. Existing required PR checks are unchanged.

Preserve every original exit, subcase and frozen qualification verdict. Analyze
original payload, sampled freshness and publication verdicts by build, repetition,
role and removal position. Compare admission queue duration, app cycle intervals,
confirmation gaps and role CPU/pressure within matched original measured phases;
do not compare whole-fixture totals after different early failures. The original
10-second observation threshold, consecutive-success requirement, quarantine,
lease and payload gates are unchanged. Missing evidence is not success.

A useful candidate must improve matched control/observation timing without new
safety failures; integration qualification still requires all original candidate
checks to pass. If controls do not reproduce, the failing low-CPU case is not
confirmed in this cohort. If candidate failures persist, a microbenchmark gain
alone is insufficient to adopt it as a fix. Retain inconclusive/negative results
privately; no retry-for-green. Two repetitions partially balance ordering, not
host trends or population variance. This instrumented workload cannot establish
release-build performance, hardware sizing or Go/Rust superiority.

Read per-live-thread /proc stat (user/system ticks, start identity, synchronous
block-I/O delay ticks), schedstat (CPU ns, runqueue delay ns, time slices), and
wchan (sampled blocked function, not duration). Verify PID/TID start identity
before and after reads. Process io provides byte counters, not wait durations.
Read robot/server cpu.stat, cpu.pressure, io.stat and io.pressure alongside these.
Record monotonic read brackets and wall time. CPU cost on the locked sampler OS
thread is recorded, including marshaling/writes in its terminal total; GC and
other threads' induced work remain outside that lower bound. Instrumentation stays ON in all four invocations; this experiment does not
estimate observer effects.

Each fixture is bounded to 361 snapshots, 128 live threads per role and a 4 MiB
JSONL file with reserved terminal space. Missing/unavailable/limited fields stay
explicit. Separate bounded export runs after original results are retained;
export errors cannot skip original validation. Telemetry qualification is
independent of product qualification. Missing files, missing terminal markers,
wrong mode/identity, capture errors or no usable samples invalidate associated
telemetry; missing rows never become zero delay. A terminal marker freezes the
original end before cleanup diagnostics. Exclude snapshots crossing/beyond that
end. Correlate original logs using wall/monotonic brackets, reporting alignment
uncertainty; post-failure evidence cannot rescue a failed original window.

Analyze matched-role/thread counter deltas only across unchanged identities and
nondecreasing counters; report sample gaps and uncovered intervals. Exited tasks'
unsampled tails and short-lived commands are missing, not zero. Cgroup counters
include child work but cannot identify an exact blocked function. Do not add
CPU, runqueue, I/O and cgroup throttle/pressure values as disjoint wall-time
components: they may overlap, use different scopes and quantization. Zero
block-I/O ticks cannot exclude I/O delay. These measurements may classify delay
but do not establish Go/Rust superiority or CPU microarchitecture causation.

Outer memory 2 GiB/no swap, PID limit 256, guest memory 768 MiB. Nonroot,
read-only root filesystem, network none, all capabilities dropped, only /dev/kvm
and its device group. Record commands, host context and CPU affinity. Affinity is
not exclusive reservation. Preserve preexisting containers and runner boot ID.
No local/remote host network, power, clock, ACL, group or service changes.

Build only on a fresh disposable GitHub runner, attempt 1. No workflow reruns.
Preparation requires 24 GiB free; compiler quota 2 CPUs/4 GiB, runtime image build
quota 1 CPU/2 GiB. The allowlisted streaming archive excludes mutable overlays,
source clones, caches, private keys and arbitrary directories; reject links,
special files and more than 12 GiB. Encrypt with the existing off-runner GPG
recipient and upload only ciphertext. Fetch/audit without changing original exits,
and replay original Go publication/failure verdicts separately from telemetry.
No remote execution is scheduled. Raw evidence stays private; public reporting,
if needed, contains only aggregate protocol/qualification.
