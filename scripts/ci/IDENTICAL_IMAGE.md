# Same-runner robot CPU quota control (experiment only; do not merge)

This new CI cohort tests whether robot CPU quota affects the reproduced capacity
failure on one runner. It does not retry or replace earlier cross-host results.
Product CLI source is fixed at 888b83b991c1857f9114c59a3deb3cb76cf8506a; the race
integration executable is fixed at 02b32013ceaf0ad36e22216335767b7dc5604965, including
its existing accounting code. The guest/controller harness uses this branch's
separately recorded clean revision. No Go source, test gates or dependencies may
change from that fixed suite revision. The harness only extends accounting to
the existing 1 CPU profile and fixes the experimental schedule.

Use one GitHub job, without a matrix. Build one Go 1.25.0 race CLI and one race
integration executable from independent clean clones, plus three pinned ordinary
compatibility executables. Build the runtime and pristine guest image once, then
verify their recorded hashes before every invocation. Record all executable,
kernel, initrd, image, runtime, compiler and controller identities. This is a new
image cohort; it is not byte-identical to the earlier harness or the same host
as a previous CI job. Only comparisons within this four-invocation cohort hold
those factors constant.

Run exactly four fresh VM invocations: robot CPU quota 0.5, 1, 1, 0.5 (ABBA).
Each uses the original 8-candidate/two-app capacity test and removal positions
0, 3, 7. Fix split role placement: robot guest CPU 0, server guest CPU 1. Server
quota remains 1 CPU, outer quota 2 CPUs, guest vCPUs 2. Fix the same two available
host CPUs for all four runs. Accounting is ON in every run, with the same
`delayacct schedstats=enable` guest boot flags, verified read-only. The same
measurement worker and limits apply to all runs. No host kernel/sysctl changes.

Only robot quota varies. Fresh VM overlays and unique result directories prevent
cross-run state reuse; two repetitions per quota partially balance run order but
do not remove host time trends, noise or establish population statistics. The
fixed 2 CPU outer budget also includes QEMU overhead: 1 robot CPU plus 1 server
CPU is not a promise of two exclusive fully available cores. Retain outer
throttling/pressure alongside guest role counters to identify this ceiling.

No API load, added retries, reordered cells, early stopping after product failure,
or freshness/lease/ownership/payload threshold changes. Retain every original
exit and frozen verdict. Infrastructure failure stays separate; host-isolation or
input hash violations stop subsequent work, retaining incomplete evidence. The
1200-second invocation watchdog bounds runtime; it is not a recovery SLO.

Analyze original failures and publication qualification by quota and repetition,
including role and removal position. Compare timing/counter deltas within matched
phases and original measured windows; do not compare whole-fixture totals when
one fixture aborts early. Retain all available and unavailable coverage, identity
turnover and timing uncertainty. A pass at 1 CPU would support quota sensitivity
under this fixed instrumented race workload, not exonerate CI, prove a single
cause, establish deployment sizing or qualify the uninstrumented release build.
No change to required PR checks or merging policy is part of this experiment.

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

Kernel definitions and limitations:
- https://docs.kernel.org/accounting/delay-accounting.html
- https://docs.kernel.org/scheduler/sched-stats.html
- https://docs.kernel.org/filesystems/proc.html
- https://docs.kernel.org/admin-guide/kernel-parameters.html
- https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
