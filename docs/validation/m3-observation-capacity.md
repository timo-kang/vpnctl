# M3 observation capacity qualification (#162)

## Scope and safety boundaries

This qualification covers local IPv4 application routing with up to eight
prepared paths and two targets. Candidate TCP proofs overlap within one common
3s window after one complete lease-maintenance sweep. Approval/cache, inventory,
kernel checks and fail-closed changes are serialized. Workers finish before the
engine releases its namespace/cache ownership. The common window also bounds
unprotected target observation; it does not grant leases to unprotected paths.

The outer observation budget remains 20s, maintenance 5s, individual TCP timeout
at most 2s, default evidence freshness 10s, and kernel lease 10s. Apply-time
validation, rollback/quarantine, approval expiry/revocation and BOOTTIME checks
remain required. Application consumes that same sweep without repeating full
maintenance after observation; apply-time live authority/lease/inventory/kernel
and actual payload verification still run. This is a bounded cooperative operation, not a hard real-time
promise against a blocked kernel or filesystem. Under CPU starvation, fail-closed
kernel expiry still takes precedence over availability.

`observation_budget_exhausted` identifies a depleted wave. Partial output cannot
reuse old success: any selected path still needs fresh consecutive confirmations
and normal apply-time proof. A report invalidated by approval expiry, clock
change or parent cancellation cannot authorize any candidate.

All network faults run inside disposable `--network none` containers and owned
namespaces. No host Wi-Fi driver/firmware, kernel installation, network setting,
clock or power operation is part of this test. Existing long experiments are
not interrupted.

## Cost evidence and original failure

[CI 37344418818](https://github.com/timo-kang/vpnctl/actions/runs/37344418818)
recorded the original 2 CPU / 2 GiB race failure: eight healthy candidates took
9.09–11.85s per observation. Watch/admission overhead broke continuous freshness.
This was an availability failure; stale success was correctly rejected.

A diagnostic-only baseline at `832238e` retains the old serial scheduler.
The external race binary SHA-256 is
`8729966c1593f501dce96ee41798e48157340bea01dd579d3fea0126bc435a43`.
Its local 2 CPU run passed; this faster host did **not** reproduce the original
all-healthy CI timing failure. The first auto confirmation took 2.780s including
0.016s admission. Eight maintenance calls consumed 2.386s and 1,184 external
commands; the entire observation consumed 1,552 commands.

The bounded-wave scheduler needs one sweep (eight renewals) instead of eight sweeps
(64 renewals). For eight successful candidates the first wave version consumed 516
external commands total, of which 148 belonged to maintenance. Further
probe-bounded sharing reduces duplicate public inventory reads; final measured
counts are recorded with the resource profiles rather than assumed constant. This removes repeat
work, not approval or kernel verification. Each candidate still has pre/post
checks and its own pinned TCP/route/WireGuard evidence.

`diagnostics` and selection `observation_diagnostics` export monotonic/BOOTTIME
elapsed time, phase calls, summed duration and external command counts/durations.
Phase time includes gate wait; concurrent/nested sums can exceed total elapsed and are
not CPU time. BPF syscalls are not counted as external commands. No command
arguments, input/output or credentials are recorded by this accounting.
The fixture also records cgroup `cpu.max`, `cpu.stat` and `memory.events`.
Missing cgroup files produce empty fields, not a claim of zero throttling.

Local raw evidence (ephemeral; CI artifacts are the shareable record):

- `/tmp/vpnctl-observation-baseline-two-cpu`: diagnostic-only baseline.
- `/tmp/vpnctl-observation-wave-two-cpu`: first mixed fixture had invalid nft
  syntax and failed before injection; its six normal 1/4/8-path cases passed.
  The overall run is **failed**, and remains preserved separately.
- `/tmp/vpnctl-observation-wave-mixed-fixed`: corrected race / 2 CPU mixed tests
  passed with the healthy path first/middle/last. First payload was 8.82/6.45/6.44s;
  every sample retained all eight leases and the independent app. The slow-probe
  pressure test passed four actual negative cycles over 17.37s, 33 lease/payload
  samples, and no busy-only substitute for the negative cycles.

## Reproducible resource profiles

Run each profile with a distinct artifact directory:

```sh
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  VPNCTL_ARTIFACT_DIR=/tmp/capacity-production-2cpu \
  scripts/test-m3-observation-capacity.sh
```

Repeat with `VPNCTL_RACE=0|1` and `VPNCTL_TEST_CPUS=1|2|4`.
Each profile covers colocated/separate controller with 1/4/8 prepared candidates
and independent targets, plus seven 2s blackholes and one healthy path at
positions 0/3/7. Mixed cases keep both target actuators running, sample all eight
kernel guards, verify real app payloads and all seven fault counters, then keep
the load running for at least 15s and three additional applied cycles per target.
Every completed steady cycle must preserve eligibility, and eligible candidate
observation gaps must stay within the unchanged 10s window. The 45s fixture watchdog is a
failure bound, not a claimed production failover SLO.

Resource measurements and final CI evidence are recorded in [#162](https://github.com/timo-kang/vpnctl/issues/162).
The first wave implementation (`7ec47cc`) passed all 54 local profile scenarios,
but [CI 37395706391](https://github.com/timo-kang/vpnctl/actions/runs/37395706391)
found two mixed-candidate race failures. A second full maintenance sweep before
apply stretched two competing app loops beyond 10s freshness, so a healthy
independent app returned to quarantine. This failed CI is retained; local
success is not substituted for it. The correction consumes the single sweep
from bounded observation and retains independent apply-time validity checks.
A regression test also expires the lease during apply revalidation and requires
quarantine. [CI 37397657290](https://github.com/timo-kang/vpnctl/actions/runs/37397657290)
then found residual starvation: one app could miss lock admission for 45s, and
competing full observations still broke continuous freshness. Neither failed
run is accepted as qualification.

The next revision tried a 1s admission window with 50–100ms jitter. It still
failed [CI 37401696768](https://github.com/timo-kang/vpnctl/actions/runs/37401696768):
one app lost eleven consecutive admission attempts, and in another case even
admitted cycles separated a healthy candidate's observations by more than 10s.
That run is retained as failed; jitter does not provide scheduling fairness.

The current revision uses a bounded FIFO admission queue for node engine calls
and node supervision in the **same cache directory**. A ticket survives the
entire wait (up to 10s including namespace admission) and lasts until ownership
is released. The old 1s retry window is replaced only for these node operations;
relay deployment admission is unchanged. Waiting obtains no approval snapshot,
renews no lease and does not extend observation freshness. Supervision reserves
its existing 5s work budget after admission, within a 15s total cycle bound.
Watch cycles keep their configured interval after completion. Existing cache
and namespace exclusion are still required; FIFO is not a global network-manager
lock and cannot schedule nonparticipating old binaries or other cache directories.

There are at most 32 live slots. Private, owned 0600 files in the existing 0700
cache directory contain only bounded ticket numbers. A short metadata flock
serializes queue enrollment, and each live descriptor holds its own slot flock.
Cancellation/normal exit/SIGKILL release descriptors; dead ticket contents carry
no authority. No PID probing, wall-clock ordering, durable replay, unbounded
waiter files or helper daemon is used. Corrupt live metadata, unsafe files, cache
directory replacement, a full queue or deadline expiry fail admission closed.
Do not manually unlink queue files while processes are running. A frozen owner
still cannot renew the independent 10s kernel lease.

Apply revalidation also removes an identical extra precheck before its existing
TCP pre/post checks. Current approval, route identity, inventory, kernel state,
lease and fingerprint checks remain, as do unbound app proof and postchecks.
Tests reject lease expiry, revocation and kernel drift before probing.

Serialized checks within one wave share only public namespace-wide
link/route/rule/mark inventories. A postcheck may reuse a snapshot only when its
command started **after that candidate's TCP finished**, with BOOTTIME age below
3s. A failed fresh read discards old data; cancellation/clock failure denies
reuse. Per-interface WG/address, underlay inventory, approvals, nft/BPF timers
and application-time checks remain fresh. The explicit pre/post live lease
checks replace only the duplicate middle LeaseStatus inside the node backend.
Tests verify freshness floors, failed reads, copied data, clock rollback and
that lease/private/interface queries are never shared. The original sampling
pressure, 45s fixture watchdog, 10s freshness and 10s lease remain unchanged.
Final corrected resource and CI results are recorded separately in #162; this
revision remains unqualified until those runs complete successfully.
Application CI returns to 2 CPU / 2 GiB for both production and race builds.
The full suites additionally test expiry, revocation, SIGKILL, drift and rollback.
Four slow-probe cycles preserve the existing minimum 8s continuous pressure
assertion now that probes overlap; safety deadlines and acceptance checks are
not widened to accommodate the optimization.

## Review and remaining operational gates

Unit race tests enforce FIFO under repeated rejoining, bounded cancellation and
queue capacity, real process death, unsafe/corrupt files and directory replacement.
They also enforce overlapping socket proofs, serialized kernel checks,
one maintenance sweep, cancellation that joins every worker, and exhaustion
that cannot produce health. Selector tests require new confirmations after a
budget failure and reject attempts to treat cost metadata as authority.

No robot-wide minimum CPU guarantee follows from container quotas on this host.
More than two active target loops, more than eight candidate paths, actual RF
hardware, mixed NetworkManager/Netplan/udev coexistence and operating SLOs remain
outside this qualification. Track them in #22/#23/#24; M3 is not closed by this
capacity change. The prior M2 24-hour result is neither restarted nor replaced.

## Independent main CI observation race (#163)

[CI 37350937241](https://github.com/timo-kang/vpnctl/actions/runs/37350937241)
passed 21/22 jobs; the direct production job failed at eight nodes because its
assertion read the previous state log 33ms before the new withdrawal publication.
Kernel peer removal and relay payload recovery had already succeeded. The fix
waits for peer removal, payload and both state publications within the same 5s
fallback deadline. It preserves the following 12s retry watch and 5s loss bound.

Five consecutive production / 2 CPU eight-node repetitions passed in
`/tmp/vpnctl-direct-log-boundary-repeat`. Fault/withdrawal timestamps are retained.
The complete production 2/3/8/32 and race 2/3/8 profiles are required in final CI.

## Fallback fixture baseline (#165)

The third CI run, [37399648534](https://github.com/timo-kang/vpnctl/actions/runs/37399648534),
passed all three mixed race positions with both apps/eight leases intact. Its
application race failure was instead the single first default-route TCP after
explicit quarantine release. The target rule/table had been removed, but there
was no pre-quarantine fallback payload or neighbour evidence; the original
packet-loss/ARP cause cannot be determined from those artifacts.

The fixed veth fixture now prepares only its own two permanent neighbours,
proves the **same target and default source** before reserving/quarantining it,
and records baseline/released route lookups, both payload results and both
neighbour inventories. Quarantine still must block new and existing TCP with
all bound probes alive. After explicit release, the original single 1s payload
check remains; no post-release retry or larger deadline is added. Baseline
readiness is setup evidence, not a relaxed protection assertion. ARP/roaming
qualification remains a separate physical-underlay test.

## Recurrent CI capacity failure and live-read consolidation (#170)

[CI 37416863772](https://github.com/timo-kang/vpnctl/actions/runs/37416863772)
reproduced the 2 CPU / 2 GiB race boundary under eight candidates/two actuators.
Healthy positions 0 and 3 first activated in 16.305/15.612s, then lost eligibility
when fresh observation gaps reached 10.097265/10.127456s. Their underlay generation
was unchanged, so this was not event invalidation. Position 7 passed but reached
9.929s between observations for the independent app. Original failures are kept;
issue #162 was reopened. The prior successful run is not a durable capacity SLO.

The follow-up replaces six per-interface WG queries with one uncached dump,
checking the same public identity, single peer, absent PSK, pinned endpoint,
allowed prefix set and disabled keepalive. It also validates the live mark.
Partial recovery permits only approved subsets; foreign state still prevents
adoption or removal. The private column and PSK stay in the original buffer,
which is erased on all exits. The format follows
[wireguard-tools dump_print](https://git.zx2c4.com/wireguard-tools/tree/src/show.c).
There is no shared/private dump cache and counters confer no health evidence.

Maintenance no longer calls LeaseStatus immediately before Lease: Lease itself
reads the BPF owner and nft timer/flowtables before any grant, conditionally
continues or requires fresh approval to rearm, then reads both enforcement gates
back. Persisted approval changes still precede a longer grant. Failure still
blocks independently. No lease lifetime, wave budget, freshness, confirmation,
FIFO or container resource bound changes. Final exact-commit CI and raw artifact
review must pass before this recurrence can be considered resolved.

## Separate robot CPU accounting (#185 / #186)

The earlier 0.5 CPU limit covered an entire one-vCPU guest: controller, relays,
robot workers and the measuring process. That profile reproduced observation
gaps over 10s and real independent-app interruption, but cannot establish a
robot-only minimum CPU requirement. The failures remain preserved. The
`c826d34` public-view copy optimization reduced the local race eight-path
`Status` benchmark from 1.460ms to 1.007–1.015ms (500 iterations, twice), with
all clock checkpoint writes/fsyncs and structural validation intact. Its
whole-VM 0.5 CPU mixed test still failed at healthy positions 0/3/7. A faster
microbenchmark is not a resolution of #186.

A separate profile places only the live robot supervisor and both target
actuators in a new guest cgroup. `clone3(CLONE_INTO_CGROUP)` applies the limit
before the processes execute, and command children inherit it. The controller,
relay supervisors and measurement process are explicitly checked to be outside
this cgroup. Initial enrollment and candidate preparation are also outside;
this profile does **not** qualify resource-constrained bootstrap or rebuilding.
The one-CPU, 2GiB outer container still limits the entire VM, with 768MiB of guest
RAM. The guest's CPU model and the outer quota remain relevant to interpretation.

Only the identity-guarded QEMU guest may create this role cgroup. No host
network, cgroup, kernel, clock or power configuration is changed. Cleanup kills
and removes only this invocation's newly created guest cgroup. Existing long
experiments remain untouched.

```sh
VPNCTL_VM_RACE=1 VPNCTL_VM_CPUS=1 \
  VPNCTL_ARTIFACT_DIR=/tmp/robot-half-new-run \
  scripts/test-vm.sh --case application-capacity-4 application-capacity-8 \
  --robot-cpus 0.5
```

The robot limit accepts `1`, `0.5` or `0.25`; use a new empty artifact directory
for each run. `VPNCTL_TEST_BINARY` can supply a deployment binary; record its
origin and digest separately from the integration suite. `VPNCTL_VM_IMAGE` may
reuse a compatible image built from the current `tests/vm` sources, not an old
agent that lacks this profile. `VPNCTL_VM_RACE=0|1` identifies the checkout build
and suite; it cannot prove how an externally supplied binary was built.

Each 4/8-path matrix positions the sole healthy target path first, middle and
last, while the other 3/7 paths remain blackholed. The configured proof budget
is 2s; an actuator stops TCP establishment at its immutable connection-latency
ceiling (1s by default) while retaining the proof budget for pre/post evidence.
Both automatic actuators remain
active, and the independent target must keep passing real TCP payloads. Every
candidate's live kernel gate is sampled. Qualification requires at least 15s
and three additional applied cycles per app, with every successful observation
gap within 10s. The original wave, freshness, authority and fixture deadlines
remain unchanged. The resource evidence includes the guest CPU model/vCPU count and before/after
`cpu.max`, `cpu.stat`, pressure and verified role placement; missing, changed, regressed
or nonadvancing counters fail validation. This is a short capacity regression,
not p95, no-uplink, long-term availability or hardware qualification.

Local race result at `6079b01`, outer VM 1 CPU, robot-only 0.5 CPU:

| Candidates | Healthy positions | Result | First payload | Largest fresh observation gap |
| --- | --- | --- | --- | --- |
| 4 | 0 / 1 / 3 | 3/3 passed | 5.953–6.228s | 3.710s |
| 8 | 0 / 3 / 7 | 3/3 passed | 7.889–8.269s | 5.347s |

Both matrices measured actual robot cgroup throttling. Evidence is retained in
`/tmp/vpnctl-capacity-robot-half`, with the original failed whole-VM profile in
`/tmp/vpnctl-capacity-clone-half`. These are local artifacts; the CI jobs upload
`m3-robot-capacity-4` and `m3-robot-capacity-8` as shareable independent results.
A local pass does not predict a slower remote runner's result.

Candidate `confirmation_gap_ns` now distinguishes a fresh successful probe whose
previous success arrived more than the policy's freshness interval earlier.
Eligibility still resets to one success and must be reconfirmed. The field is
absent on a new sequence, after normal recovery, or when a previous unknown or
failure had already broken continuity. It diagnoses the observed gap without
attributing it to CPU, the network, or a particular lock by inference alone.

#185 still needs deployment-representative CPU/storage, startup/rebuild and
longer load profiles. #186 retains the original CI failure with incomplete
terminal diagnostics: a newer pass cannot retroactively prove its root cause.
Whole-VM low-budget failure, role-limited success and original CI failure must
remain separate evidence. M2's successful 24h baseline and M3's other release
gates are not changed by these short runs.

## Policy-bounded TCP establishment (2026-10-07, #185)

[CI 37595610104, CPU8](https://github.com/timo-kang/vpnctl/actions/runs/37595610104/job/112707371519)
failed all three healthy positions despite successful independent-target TCP and
WireGuard observations. Their 10.07–11.87s gaps broke the unchanged 10s confirmation
window and caused real application quarantine. The fixture never runs the direct
engine. This is not a cgroup-evidence parsing failure or proof that CPU throttling
alone caused the delay. Public diagnostics show maintenance, observation and
admission costs; the source behavior predates this PR.

A candidate connect taking over the policy's `MaxConnectTime` cannot be selected,
yet a 2s proof timeout previously kept waiting beyond the default 1s ceiling.
The actuator now limits only TCP establishment to that immutable policy ceiling.
Pre-connect route/counter reads and post-connect route/counter/ownership checks
retain their original parent budgets. Raw `ObserveTarget` has no selector policy
and keeps its existing timeout. The selector still validates the measured
connection duration, two consecutive proofs, 10s freshness and all authority.
The inclusive `<=` boundary is retained; the connection context expires one
nanosecond beyond it. This is deadline arithmetic, not a nanosecond scheduling SLO.

Deterministic tests reproduce the unnecessary blackhole wait and an initially
incorrect exclusive deadline. They cover a 900ms connect plus 200ms evidence on
each side, exact 1s success, a custom 1.5s policy, a shorter parent deadline,
missing WG counter growth, policy propagation, unrestricted diagnostic calls and
cancellation that joins every worker. The recorded CPU8 timestamps separately
reproduce lost eligibility; they are not a performance simulation.

At source `3fa9aa2`, production VM tests with robot-only 0.5 CPU passed all six
cases (4/8 candidates, healthy first/middle/last). First payload was 3.256–3.285s
for four candidates and 4.065–4.237s for eight; the largest eligible observation
gap was 2.056s and 2.758s respectively. Both applications and all kernel leases
remained valid through at least 15s and three further applied cycles. Evidence:
`/tmp/vpnctl-fix-cpu-connect-v1`. The prior failed CI stays failed; this local result
does not replace exact-head remote CI or establish a minimum robot CPU guarantee.

The same production source also passed all six robot-only 0.25 CPU cases in
`/tmp/vpnctl-fix-cpu-connect-quarter-v1`: four-path first payload 4.590–4.680s,
maximum gap 3.301s; eight-path first payload 6.307–6.501s, maximum gap 4.499s.
Race instrumentation has a separate cost profile and requires its own result.

At clean source `896a53b`, the CI-equivalent race build also passed all six
robot-only 0.5 CPU cases in `/tmp/vpnctl-fix-cpu-connect-race-v1`. Four-path
first payload was 3.971–4.158s and its largest fresh observation gap was 2.679s;
eight-path values were 5.987–6.371s and 4.423s. Every position retained both
application payloads and all candidate leases for at least 15s and four additional
applied cycles per app. This is separate local evidence; remote CI and the
deployment/startup/long-duration qualifications above remain required.

Remote [CI 37602539188](https://github.com/timo-kang/vpnctl/actions/runs/37602539188)
at `b4a95c7` also passed the race robot-only CPU8 profile in all three healthy
positions. First payload was 8.201–9.026s, and the largest fresh observation gap
was 5.906s, below the unchanged 10s boundary. Both applications and all leases
passed through at least 15s and three further applied cycles. These values are
rounded upward where used as bounds. The run's separate candidate lifecycle
unit-test failure is retained; a passing CPU job does not make the entire run pass.


## Recurrent CPU8 freshness failure (2026-10-07)

[CI 37604001478, CPU8](https://github.com/timo-kang/vpnctl/actions/runs/37604001478/job/112740060969)
at `b119603` failed healthy positions 0 and 7. The runtime was unchanged from
`b4a95c7`; this newer failure supersedes any assumption that the earlier CPU8
pass established capacity. Fresh successful proofs were 10.662s apart at
position 0 and 10.727s / 10.685s apart at position 7, resetting confirmation and
quarantining the application. Position 3 passed with a largest gap of 9.988s.
The unchanged 10s policy correctly rejected stale continuity.

The failed guest reported EPYC 7763 versus EPYC 9V45 in the earlier passing run.
Both used one guest vCPU and a robot-only 0.5 CPU quota. Approximate CPU rates,
using cgroup bandwidth periods corroborated by worker timestamps, were 0.98 CPU
for the whole guest, 0.48 for the robot and 0.50 elsewhere. Robot throttling was
nearly absent. Whole-guest saturation is supported; CPU model alone is not a
proved cause. Controller, relay and measurement costs are not individually
separated in these artifacts, and host-QEMU pressure was not recorded.

Median supervisor maintenance grew from 0.621s to 1.395s, app work excluding
admission from 2.414s to 3.948s, and app2 from 1.819s to 3.918s. FIFO order stayed
intact; its participants held ownership longer. Concurrent phase sums cannot be
added as wall time. A stable supervisor/app/app2 cohort executes about 767 child
processes, including roughly 120 fresh `cat` reads of `rp_filter`.

Optimization ledger (all checks and freshness limits retained):

| Candidate | Measurement | Decision |
| --- | --- | --- |
| Fresh bounded native `rp_filter` reads | 1,000 reads × 3, race, Ryzen 9800X3D: original command 260.659–267.245µs/read; native command path 4.222–4.721µs/read | Kept: roughly 120 fewer children per cohort in the VM; no cached settings or skipped checks |
| FIFO polling | Two 25ms waiters: 0.0119–0.0136 CPU production, 0.0315–0.0318 race on the same local CPU | Measured wait-only predecessor hint; same cadence, full validation before every admission |
| Repeated public inventory decoding | Not yet isolated in a representative profile | No speculative cache added |

A separate, stricter diagnostic limits the whole local VM to 0.5 CPU while
retaining the robot's 0.5 quota. The original clean `b119603` passed positions
0 and 3 (maximum gaps 8.798s and 9.103s) but failed position 7 with
`application lost fresh continuous eligibility`. Its evidence is retained at
`/tmp/vpnctl-cpu-baseline-half-v1`; this is distinct from the remote qualification
profile and does not replace it. The native-read comparison in `/tmp/vpnctl-cpu-native-half-v1` passed all three
positions and reduced the measured child-process work (supervisor 76 to 60
kernel commands; complete app cycles roughly 52–54 fewer). Related five-package
race tests, full vet and independent boundary review passed. Missing, oversized,
symlink, FIFO and cancelled reads fail closed. Every pre/post check still reads
both current settings; nonzero or malformed values remain conflicts.

End-to-end headroom remains insufficient: the largest steady eligible gap was
9.706s, and app2 recorded 10.157–10.295s confirmation gaps during initial
activation. A pass in this short fixture is not a claim that all gaps disappeared
or that the slower remote profile is resolved. The original failures remain
retained. FIFO polling cost is addressed below; final same-profile comparison and
exact-head CI remain required before merging.


### Bound the cost of waiting without changing admission authority

The FIFO queue now retains the last fully validated predecessor's slot, ticket
and inode as a waiting hint. Each 25ms poll freshly opens and validates the
metadata file and that slot. A still-locked matching predecessor can only keep
the caller waiting. Allocation, admission and every changed or missing hint
still require the original complete 32-slot scan under the metadata lock.
Cancelled contexts stop before filesystem work; no cached approval or lease is
introduced. Other corruption may remain unobserved while blocked, but is always
checked before any turn can be granted.

Independent review rejected the first hint implementation: an unlocked-slot
`flock` probe outside the metadata lock could briefly look like a live queue
member and falsely return `ErrAdmissionFull` with only 31 actual tickets.
A controlled preemption with real files/locks reproduced it. The final hint
holds the metadata lock and closes the probed slot before releasing that guard;
the same reproduction passes. No production test hook was added.

Real inotify regressions require at most two files per blocked poll, forbid
slot inspection during metadata publication, and require a complete scan after
an inode change even if its ticket is identical. Tests cover partial publication,
rename, replacement, symlink, wrong permissions, corruption, same-inode ticket
reuse, FIFO rejoin, cancelled waits and real process death. The full relaycache
race suite and independent review passed.

The same two-waiter, 25ms, 5s × 3 benchmark reduced CPU from 0.0119–0.0136 to
0.00314–0.00320 cores in production and from 0.0315–0.0318 to 0.00512–0.00614
with race instrumentation. Tight per-poll CPU fell from 106–108µs to
6.71–6.73µs production, and from 294–297µs to 17.68–18.12µs race. These are
local Ryzen 9800X3D measurements; the end-to-end VM qualification is separate.


The combined implementation at clean `137fafd` passed the same stricter local
race VM comparison (whole VM 0.5 CPU, robot quota 0.5 CPU). All three healthy
positions retained both actual payloads and all eight candidate leases through
at least 21s and three further applied cycles per application:

| Healthy position | First payload | Steady observation window | Largest fresh eligible gap |
| --- | --- | --- | --- |
| 0 | 12.203s | 21.791s | 7.812s |
| 3 | 11.311s | 22.086s | 8.200s |
| 7 | 13.796s | 24.225s | 8.907s |

Evidence: `/tmp/vpnctl-cpu-native-hint-half-v1`. The recorded rows contain no
confirmation-gap reset; the original failed position 7 had a 10.892s
confirmation gap. The intermediate native-read-only result and its marginal
9.706s bound remain recorded above. This is a finite diagnostic on the same
local hardware, not a guaranteed minimum CPU specification or p95 estimate.
Final remote CI uses its original whole-VM 1 CPU / robot 0.5 CPU profile, including
separate four- and eight-candidate cases. Its pass is required independently.

## Observation ordering investigation (2026-10-08, #193)

A separate deterministic scheduling counterexample runs the actual observation
and default selector paths with fake kernel/transport boundaries. With eight
100ms prechecks, a 900ms healthy TCP proof, seven 1s failures, and cycle starts
9.5s apart, all proofs overlap and each wave completes within 3s. Moving the
healthy candidate from first to last precheck admission in the third wave changes
its proof interval from 9.5s to 10.2s. The unchanged selector correctly resets its
confirmation count from two to one and clears the desired path. Merely launching
goroutines in catalog order does not control their admission order.

The reproduction, including a race RED run, is preserved in
`/tmp/vpnctl-observation-order-repro`. This proves an independent source of
confirmation jitter; it does not identify the missing failure cycle of #186.
Nor does it explain away the 6.083s second admission and 22.007s first payload
recorded in the final PR #192 remote CPU8 run. Stabilizing local precheck order
cannot remove CPU saturation, filesystem delays, long admission waits, or
changes in the candidate population or actual transport timing.

### Measurements and rejected alternatives

Diagnostic builds based on main `9fe6147` ran the eight-path/two-application race
fixture with both the whole VM and robot quota at 0.5 CPU on the same local
hardware. `/tmp/vpnctl-startup-profile-v1` records parent Go CPU profiles;
`/tmp/vpnctl-startup-profile-v2` also records child user/system CPU, without
arguments, command input, or secrets. All three healthy positions passed in
both baseline runs. The latter first-payload samples were 12.832/11.204/13.305s
(positions 0/3/7); app/app2 maximum fresh-observation gaps were
8.792/9.149s, 7.471/7.803s and 8.815/9.524s. They are individual observations,
not percentile estimates or deployment minimum specifications.

Parent Go CPU profiles omit child CPU. For example, position 3's first watcher
used 1.78s of Go CPU over 34.29s in the first diagnostic. In the second diagnostic,
the same role issued 300 nft reads totaling 0.545s child CPU and 2.185s summed
command wall time. Other positions/roles issued 300–380 nft reads. Summed child
wall durations can overlap and are not total elapsed time.

Two proposed optimizations were rejected before commit:

- Decoded ownership-inventory reuse: a realistic eight-candidate benchmark cost
  only 25.08–25.49ms for 16 race snapshots, or 87.51–89.60ms for 56. This isolated
  JSON parsing measurement cannot explain seconds of admission delay; it does
  not justify another cache. Source/overlay/profiles are preserved in
  `/tmp/vpnctl-inventory-parse-profile-fj4eryvb`.
- Combining `nft list flowtables` and a table-scoped lease read in one invocation:
  actual nft 1.0.9 emits two JSON documents, and more seriously **omits foreign
  flowtables from the first document** when combined with the scoped table read.
  Standalone reads see the installed object in each of `inet`, `ip`, and `ip6`.
  The real protocol test rejected the candidate in
  `/tmp/vpnctl-startup-profile-v4`; its bounded worker failure is in
  `observer.jsonl` under `failure-diagnostics`. Standalone/batch comparisons are
  in `/tmp/vpnctl-nft-protocol-diagnostic-v4`. These short protocol probes are
  diagnostic only, not capacity passes. The earlier malformed candidate run
  `/tmp/vpnctl-startup-profile-v3` and all intermediate diagnostics remain
  preserved. The experimental source is archived in
  `/tmp/vpnctl-rejected-nft-batch`. Main retains independent fresh nft reads;
  no lease/flowtable cache or combined invocation is shipped.

### Ordered precheck admission

Each wave now links its actual jobs in catalog order. A job's precheck waits for
its predecessor's precheck to finish, including failure or cancellation; then
both prechecks and postchecks use the existing shared check gate. Releasing a
precheck lets the next candidate proceed without waiting for TCP. All workers
are still joined before releasing cache/namespace ownership. Policy-excluded
candidates retain their diagnostic rows and lease maintenance but do not create
holes in the admission chain. A single-candidate revalidation remains unchanged.

This adds no approval, timer or kernel-state cache. It does not change the 3s
wave, 10s freshness, TCP limit, selector thresholds, or kernel enforcement.
Candidates late in catalog order still need sufficient budget; order is not a
substitute for capacity qualification. Population/catalog changes and differing
postcheck or transport costs may still shift proof timestamps.

The original forced-arrival selector counterexample now retains a 9.5s proof
gap, two confirmations and the same healthy desired path even when goroutines
arrive in reverse position. Both versions retain eight overlapping proofs. The
fixed-source overlay and evidence are preserved separately under
`/tmp/vpnctl-observation-order-repro-fixed`; the original RED is untouched.
Permanent tests exercise actual multi-wave admission with all eight and six
policy-included candidates, reverse arrivals independent of runtime scheduling,
reversed proof completion, first-precheck failure, cancellation and the exact
wave deadline. These are scheduling/functional assertions, not CPU benchmarks.

Self-review also found a deadline-reporting race in synthetic time: a candidate
could finish at exactly 3s with all paths unknown and all workers joined, while
the shared context had not yet published its deadline error. The batch omitted
`observation_budget_exhausted`. The final check now also compares the actual
shared deadline after joining workers. The strict test requires the reason as
well as the unchanged hard deadline and zero healthy evidence; it does not
accept a missing diagnostic as a successful deadline check.

The ordered-admission diagnostic build (before the final deadline-reporting
adjustment) passed all three eight-path positions with the same whole-VM 0.5 CPU,
robot 0.5 CPU, race and profiling setup as the baseline above. Evidence:
`/tmp/vpnctl-startup-order-profile-v1`.

| Healthy index | First payload | Maximum app gap | Maximum app2 gap |
| --- | ---: | ---: | ---: |
| 0 | 11.462s | 7.164s | 7.663s |
| 3 | 12.104s | 7.295s | 7.707s |
| 7 | 11.119s | 8.194s | 8.018s |

The position-3 startup is slower than its single baseline sample; these samples
show functional success and preserved freshness under this local profile, not a
statistically established performance gain. Final uninstrumented source and
remote CI evidence are required separately before merging.


## Candidate-local endpoint collection and manager recovery follow-up (#195)

The manual CI run [37642463237, manager-install-8](https://github.com/timo-kang/vpnctl/actions/runs/37642463237/job/112864710186)
failed at `flap-up-0` on `9d11887`. The alternate `p01` remained applied while
`p00` spent about 100 seconds rebuilding. Its first healthy proof arrived at
109.247 seconds and the next at 116.406 seconds; the default recovery hold-down
had not elapsed at the fixture's 120-second limit. The independent PR run
[37642751898](https://github.com/timo-kang/vpnctl/actions/runs/37642751898) on the
same commit passed all checks; its first `flap-up-0` proof was at 20.383 seconds
and convergence at 33.241 seconds. One passing run does not resolve the failed
run. Both records are retained. No budget or hold-down was increased.

A separate deterministic reproduction found that each preparation unit, already
limited to one underlay, still collected other approved relay endpoints on that
underlay. With the real `LinuxCollector` and only its process boundary replaced,
an unrelated route query exhausted the existing 750ms rebuild deadline. This
blocked both the first and last candidate in the eight-path catalog, even when
the requested route was healthy. The observed CI inventory cost was only about
40–100ms per turn, so this injected stall is not a retrospective diagnosis of
that CI incident.

Preparation now narrows the collector input to the requested endpoint from the
current catalog, and only when `Build` has included it in the approved inputs.
The complete catalog, authority/binding validation, original slot allocation,
current route and before/after link checks remain. Each work unit recollects its
inventory. Previous removal identity does not authorize an endpoint. Disabled
and draining candidates remain ineligible. Kernel ownership,
collision checks and all creation/cleanup budgets remain unchanged.

Regression evidence: normal and race RED reproduced the unrelated-endpoint
stall; GREEN performs one requested route read plus both link snapshots, with
zero unrelated reads. Current route failure and link replacement still reject
approval, and source changes are collected afresh. The endpoint guard mutation
is checked separately using a Go overlay without altering the product source.
The manager comparison results are tracked separately; no general CPU
capacity improvement or resolution of the 120-second failure is inferred from
this isolation fix alone.


## Reusing the remaining preparation quantum (#195)

The matched local manager-install-8 baseline and endpoint-isolation candidate
both passed all 28 steps on AMD Ryzen 7 9800X3D at whole-VM 0.5 CPU with the
same cached image, without race instrumentation. Flap-up 0/1 convergence was 32.209/30.470 seconds before
and 33.275/30.378 seconds after. These single samples do not show a speedup or
reproduce the remote failure. Endpoint isolation remains justified by its
independent deadline-stall correctness regression, not those timings.

A further independent production-scheduler reproduction found that finalizing
one candidate ended the entire quantum, even with 650ms of the 750ms budget
left and another fully installed, closed candidate awaiting final validation.
Two 100ms readbacks therefore required two admissions. The loop now continues
within the existing budget, remembering completed paths only until this call
returns. It does not treat completion as lease evidence or update `maintained`.
Both readbacks can finish in one 200ms quantum in the deterministic fixture.

The 500ms BOOTTIME and wall-clock reserve, 8-unit limit, fresh approval, current
inventory/ownership checks and durable journal boundaries remain unchanged.
Tests forbid creation and lease calls during finalization, reopen the actual
journal, and check interrupted saves before and after persistence. Cancellation,
authority denial, changed underlay, failed kernel readback and expired budget
remain closed; a new admission without fresh lease maintenance still rejects
the prepared candidate. This saves a demonstrably unnecessary admission but
does not establish an upper bound on arbitrary host contention. The original
remote failure and deployment capacity qualification remain separately tracked.


## Manager fixture priority collision and early evidence (#197)

The `40d189e` [manager-install-8 CI failure](https://github.com/timo-kang/vpnctl/actions/runs/37648920742/job/112886809459)
failed before fault injection, at the stable-baseline barrier. This was a different
incident from #195's slow preferred-path rebuild. The captured application
reservation and the fixture's unrelated VPN rule both used priority **32000**.
Application reservations span 32000..32759, so the fixture's fixed value could
collide with a randomly assigned application reservation. The primary app stayed
in `target_quarantine_conflict`; the independent app remained active. The
product correctly refused the foreign collision, and that rule is unchanged.

The fixture now uses priority **32761**, outside candidate/probe and application
reservations, after its fallback32760 and before main32766. Creation and all
preservation checks use the same constant. Replaying the captured ownership
tuples confirms that the original collision prevents mutation; with the fixture
priority outside the reservation, owned application-route cleanup succeeds while
preserving both the terminal guard and foreign rule.

The old trace began only after the stable baseline passed, leaving this failure
without full application cycles. Passive log readers and their cleanup now
start before fixture setup. Packet samplers still start only after the original
baseline barrier; bootstrap load and readiness thresholds are unchanged. The
host-safe regression retains both applications' initial failed cycles without
opening sockets and retains them after early shutdown. Removing passive reader
startup makes that regression fail. The bounded log/cycle/packet limits remain.


## Cleanup behind a deferred creation (#201)

The clean `4ec7782` [manager-auto-8 run](https://github.com/timo-kang/vpnctl/actions/runs/37655099506/job/112908097254)
failed the 120-second preferred-recovery bound on an AMD EPYC 7763 runner with
one CPU for the entire VM. Baseline, manager/link loss, all-relays-down and alternate recovery
passed first. The alternate remained verified during preferred recovery. This is
an executed integration failure, separate from that run's unstarted jobs whose
GitHub annotations report repeated runner acquisition failures.

The retained cycles show slow forward progress, without preparation-step resets.
Admission waiting dominated the sampled supervision cycles. One independently
reproduced contributor was a waiting/preparing/ready candidate ending the queue
scan when fewer than 500ms of the 750ms quantum remained. A later owned cleanup
could still fit that remainder, but it waited for another admission instead.

The scheduler now scans beyond such candidates for idempotent removal work.
Once it skips a creation candidate, it retains the prior durable scheduling
cursor while completing opportunistic cleanup. The deferred creation therefore
keeps priority after a process restart and a new admission. Cleanup-only queues
retain normal round-robin order. No additional journal field or fsync is needed.

Independent normal/race tests reproduce the blocked cleanup with 450ms remaining,
then verify progress through real temporary journal writes and reopen. They also
cover creation fairness on the next admission, unchanged candidate state,
closed leases, ownership changes, cancellation, shared wall/BOOTTIME expiry,
backoff, no eligible removal and the eight-unit bound. Allowing the cursor to
advance past the skipped creation makes the restart fairness regression fail.

The 750ms budget, 500ms creation reserve and live ownership/authority checks are
unchanged. This removes a demonstrated wasted admission; it does not prove that
the original remote 120-second bound now holds under arbitrary contention.
The broader recovery and deployment-capacity work remain in #195 and #185.


## Repeated remote CPU8 failure and outer-container evidence (2026-10-08)

The combined `c77faaf` revision failed [CPU8 run 37658075568](https://github.com/timo-kang/vpnctl/actions/runs/37658075568/job/112918231410)
on EPYC 9V74, with the unchanged race build, one guest vCPU, whole-VM 1 CPU,
and robot-only 0.5 CPU profile. Positions 0 and 3 passed. Position 7 recorded
successful app proofs 10.656s and 10.776s apart and one exhausted 3s wave;
app2 subsequently had an 11.437s interval and was quarantined. The 10s
freshness rule correctly rejected the lost continuity. The raw failure is
preserved in `/tmp/vpnctl-final-cpu8-failure`; this is a real execution failure,
separate from earlier GitHub runner-acquisition errors. PR #200 was not merged.

Robot cgroup throttled time grew by only about 0.168s during the failed
position. Long ownership waits and increased maintenance/proof times remain
visible, but the original artifact has no outer QEMU-container usage/pressure
interval. Robot quota exhaustion, whole-guest competition, and outer-container
throttling cannot be treated as interchangeable explanations.

The observer now records `container_resources` on every case, including a
failed exercise. Its scope is **QEMU plus observer in the bounded outer
container**. Before/after samples contain `cpu.max`, `cpu.stat`, `cpu.pressure`,
and monotonic start/end timestamps surrounding each sample. The interval
includes guest boot and fixture setup; it excludes failure diagnostics and VM
teardown. It is neither per-position nor robot-only accounting. Read errors,
empty/oversized files and invalid text mark that file unavailable instead of
inventing zero usage. Diagnostic availability does not change the original
completed/qualified result or mask its exception. Unit regressions verify both
success/failure preservation and missing-data handling.

Two unchanged local `c77faaf` race baselines used the same cached image,
Ryzen 9800X3D, whole-VM 0.5 CPU and robot 0.5 CPU. Both passed all three
positions. Their largest fresh gaps were respectively 7.792s and 8.621s;
first payload ranged from 11.319s to 12.381s. Artifacts are
`/tmp/vpnctl-precheck-barrier-baseline` and
`/tmp/vpnctl-precheck-barrier-baseline-2`. These samples demonstrate local
variation, not a fix or reproduction of the remote capacity failure.

A separate deterministic scheduling counterexample uses eight 180ms
prechecks, eight 160ms postchecks, seven 10ms failed TCP attempts and a final
900ms healthy TCP. Early postchecks delay the final TCP start to 2.4s, so the
existing 3s wave expires. Prioritizing all prechecks could fit this workload in
2.72s, but would block an earlier healthy candidate's postcheck behind a late
stalled precheck. That unconditional barrier was rejected; no scheduler or
freshness policy change is included. The independent RED and safety controls
are preserved in `/tmp/vpnctl-postcheck-priority-repro-vgraht0s`.

The deployment resource envelope and separation of controller/relay/measurement
CPU from the robot remain open under #185. Additional diagnostic data is not a
capacity pass or an M3 deployment qualification.
