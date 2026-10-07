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
last, while the other 3/7 paths time out for 2s. Both automatic actuators remain
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
