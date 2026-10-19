# Runtime accounting OFF/ON cross-host control (experiment only; do not merge)

This is a new instrumentation cohort, following the completed exact-image
comparison. Never rerun, overwrite or replace that comparison. Product CLI source
remains 888b83b991c1857f9114c59a3deb3cb76cf8506a. The test executable and guest
harness use this experiment's separately recorded clean commit. No product
packages, original payload/publication gates, lease limits or policy change.
CI builds one Go 1.25.0 race CLI and race integration executable and three pinned
ordinary compatibility executables from independent clean clones. Runtime,
pristine guest qcow2, kernel, initrd, all executable bytes, actual build settings,
suite revision and tool/protocol SHA-256 inventory travel together. The remote
host MUST NOT rebuild, update packages or alter this set.

Each host runs exactly four fresh VM invocations: counters OFF, ON, ON, OFF.
All use the original 8-candidate/two-app capacity case, three removal positions,
2 outer CPUs/2 guest vCPUs, robot quota 0.5 CPU on guest CPU 0, server quota 1 CPU
on guest CPU 1. No API load, extra retries, reordered cells, early stopping after
product failure, or freshness/lease/ownership/payload threshold changes. Original
exits and frozen verdicts are retained. Infrastructure failure stays separate;
host-isolation or input hash violations stop subsequent work, retaining an
incomplete result. Watchdog is 1200 seconds per invocation, not a recovery SLO.

Both OFF and ON boot the guest with `delayacct schedstats=enable`, verified
read-only before fixture launch. These flags have their own overhead, so OFF is
not interchangeable with the older cohort. No host sysctl/kernel changes. OFF
writes only metadata and checks identities, with no periodic /proc reads. ON
samples at 1 Hz from the measurement worker in the server cgroup: registered
measurement, supervisor, controller, two relays and both apps. Registration occurs
before app2 activation to cover the previous prequalification failure. Scheduling
may delay or skip sampling intervals; no guaranteed cadence or interpolation.

Read per-live-thread /proc stat (user/system ticks, start identity, synchronous
block-I/O delay ticks), schedstat (CPU ns, runqueue delay ns, time slices), and
wchan (sampled blocked function, not duration). Verify PID/TID start identity
before and after reads. Process io provides byte counters, not wait durations.
Read robot/server cpu.stat, cpu.pressure, io.stat and io.pressure alongside these.
Record monotonic read brackets and wall time. CPU cost on the locked sampler OS
thread is recorded, including marshaling/writes in its terminal total; GC and
other threads' induced work remain outside that lower bound. OFF/ON outcome and
resource comparison, not that lower bound alone, assesses observer effects.

Each fixture is bounded to 361 snapshots, 128 live threads per role and a 4 MiB
JSONL file with reserved terminal space. Missing/unavailable/limited fields stay
explicit. Separate bounded export runs after original results are retained;
export errors cannot skip original validation. Telemetry qualification is
independent of product qualification. Missing files, missing terminal markers,
wrong mode/identity, capture errors or no usable ON samples invalidate associated
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

Outer memory 2 GiB/no swap, PID limit 256, guest memory 768 MiB. Nonroot, read-only
root filesystem, network none, all capabilities dropped, only /dev/kvm and its
device group. Freeze two available host CPUs and record every command. Affinity
is not exclusive reservation. Record host context and preserve the same running
containers/boot ID. No host network, power, clock, ACL, group or service changes.

Build only on a fresh disposable CI runner, attempt 1. Preparation requires
24 GiB free, compiler quota 2 CPUs/4 GiB, runtime build quota 1 CPU/2 GiB.
Allowlisted streaming archive excludes mutable overlays, source clones, caches,
private keys and arbitrary directories; reject links/special files and >12 GiB.
Encrypt to the existing off-runner GPG recipient; upload encrypted evidence only.
Remote verifies archive, full manifest, runtime/executable/image identities and
protocol before one fixed launch. Replay original Go publication/failure verdicts
and audit resource/role constraints separately from new telemetry. Retain all
four outcomes per host, including incomplete evidence. Raw measurements remain
private/encrypted; public reports are aggregate protocol/qualification only.

Kernel definitions and limitations:
- https://docs.kernel.org/accounting/delay-accounting.html
- https://docs.kernel.org/scheduler/sched-stats.html
- https://docs.kernel.org/filesystems/proc.html
- https://docs.kernel.org/admin-guide/kernel-parameters.html
- https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
