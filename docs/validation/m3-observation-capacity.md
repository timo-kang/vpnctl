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
remain required. This is a bounded cooperative operation, not a hard real-time
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

The new scheduler needs one sweep (eight renewals) instead of eight sweeps
(64 renewals). For eight successful candidates the same checks consume 516
external commands total, of which 148 belong to maintenance. This removes repeat
work, not approval or kernel verification. Each candidate still has pre/post
checks and its own pinned TCP/route/WireGuard evidence.

`diagnostics` and selection `observation_diagnostics` export monotonic/BOOTTIME
elapsed time, phase calls, summed duration and external command counts/durations.
Phase time includes gate wait; concurrent sums can exceed total elapsed and are
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
the load running for another 5s after activation. The 45s fixture watchdog is a
failure bound, not a claimed production failover SLO.

Resource profile results and final CI evidence are recorded after execution.
Application CI returns to 2 CPU / 2 GiB for both production and race builds.
The full suites additionally test expiry, revocation, SIGKILL, drift and rollback.
Four slow-probe cycles preserve the existing minimum 8s continuous pressure
assertion now that probes overlap; safety deadlines and acceptance checks are
not widened to accommodate the optimization.

## Review and remaining operational gates

Unit race tests enforce overlapping socket proofs, serialized kernel checks,
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
