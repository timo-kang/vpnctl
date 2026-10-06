# M3 owned candidate rebuilding (#171)

## Contract and review findings

This qualification covers explicitly opted-in node application candidates, with
at most eight candidates and two local application targets. See the
[operational contract](../architecture/node-candidate-preparation.md) and
[deployment workflow](../deployment/node-application-routing.md).

Rebuilding is split into durable, bounded work after lease maintenance. It does
not adopt manual candidates, authorize communication, change physical manager
configuration, or extend the 10s lease / 10s observation freshness. Missing consent
cannot resurrect a released candidate even if its previous journal survives a
failed rewrite. A failed admission/unlink/directory sync is not a committed release.

Self-review and real-kernel testing found and corrected two integration defects:

- A rebuilding candidate's OIF-less terminal-route deletion invalidated every
  underlay and could interrupt an independent app. Event scoping now requires the
  exact current journal table/random metric and canonical protocol-186 terminal
  route. Unregistered/retired/foreign tuples and unknown attributes remain global.
- Exact device-bound probe resources in preparing/removing phases must remain
  recognizable as owned while another target continues. This exemption grants no
  candidate eligibility; source-only or altered rules still conflict.

A fully prepared owner also retains strict alias/key validation throughout
cleanup, and final removal verifies that lease tables and pinned BPF objects are
absent. Foreign ownership is preserved at each incremental deletion.

## Coverage and reproducibility

```sh
VPNCTL_RACE=0 VPNCTL_ARTIFACT_DIR=/tmp/preparation-production \
  scripts/test-m3-preparation.sh
VPNCTL_RACE=1 VPNCTL_ARTIFACT_DIR=/tmp/preparation-race \
  scripts/test-m3-preparation.sh
```

The default runner limits each disposable `--network none` container to 2 CPU /
2 GiB. It creates its own network namespaces and dedicated bpffs. No host Wi-Fi
driver/firmware, kernel image, network setting, clock, suspend or reboot changes
are performed. Existing experiments are not stopped or replaced. The runner also
accepts `VPNCTL_TEST_BINARY` for a binary built by a deployment repository.

| Test | Required evidence |
| --- | --- |
| `PreparationRecovery` | Actual endpoint deletion, source and gateway change, down/up route loss, rename/return, physical deletion/recreation with changed and reused ifindex; new owner, new confirmations and actual unbound payload; independent app continuity; explicit release does not resurrect. |
| `PreparationCapacity` | All eight explicitly managed; healthy path at positions 0/3/7 with seven real TCP blackholes; two concurrent app loops; one affected candidate rebuilt; seven independent leases maintained during repair and all eight after it; both app payloads and observation gaps ≤10s. |
| `PreparationCrash` | Real SIGKILL immediately after ten installation mutations and six deletion mutations; journal reopening, no duplicate adoption, fresh authenticated rearm and actual payload. |
| `PreparationENOSPCOptOut` | Real private-cache tmpfs exhaustion after engine admission; consent removal succeeds, larger journal replacement fails with ENOSPC; prior journal remains, reopened supervision cleans without resurrection. This specifically tests mid-operation failure, not a successful release when initial admission fails. |
| `PreparationForeignState` | Foreign alias, mark, peer, PSK, target route/rule, tc/nft additions, rp_filter and physical address changes are preserved across retries; other app stays live; convergence after fixture-owned fault removal. No PSK is logged. |

Capacity runs record cgroup CPU and memory events and sample the long-lived
supervisor and both app processes. Each worker must remain within 128 descriptors
and 512 MiB RSS, in either build profile; measured peaks are exported. These are
qualification ceilings, not claimed minimum deployment resources or an indefinite
leak proof. The unchanged container quota remains the outer bound.

Unit/race coverage includes explicit opt-in/manual separation; stale disk
approval cannot rearm; revocation at each installation stage; actual approval
expiry during early/middle/final preparation followed by fresh-only recovery;
source constraints, unavailable/unknown inventory; persistent round-robin/backoff
and BOOTTIME exhaustion; interrupted adds before/after mutation; 34 creation and
16 removal journal boundaries both before and after durable write; release
failure at multiple phases; and unsafe/corrupt consent files and sync failure.
Kernel authority, target selection and application-time verification remain
covered by the existing node/application suites.

## Local evidence and retained failures

Local paths are ephemeral; the PR's complete CI runs and uploaded artifacts are
the portable record. A passing subset does not turn its containing failed run
into a pass.

- `/tmp/vpnctl-preparation-production-v4` and `...-race-v4`: capacity at all three
  positions passed (172.71s / 199.34s total), all 16 real crash boundaries passed
  (20.62s / 40.63s), and all seven physical recovery cases passed
  (169.11s / 173.70s). The overall runs failed on two harness defects below.
- `/tmp/vpnctl-preparation-production-v5` and `...-race-v5`: corrected ENOSPC
  boundary passed (9.41s / 12.53s), and all ten foreign-state cases passed
  (127.44s / 133.91s).
- `/tmp/vpnctl-preparation-all-unit-final.log`: full `go test ./...`.
  `/tmp/vpnctl-preparation-race-unit-final.log`: affected apply/cache/observe/event
  and CLI packages with the race detector. The subsequently added expiry/offline
  test also passed independently with `-race` (6.00s).
- `/tmp/vpnctl-preparation-vet-final.log`: `go vet ./...`; shell syntax and
  `git diff --check` were also checked.
- `/tmp/vpnctl-preparation-resource-production` and `...-resource-race` are the
  follow-up capacity runs with explicit per-worker FD/RSS assertions. Their
  completion and exact-head CI verdict are recorded in #171 / its PR, separately
  from the preceding measurements.

Earlier artifacts remain retained, including failures:

- `...-kernel-v1`: the independent-app terminal-route invalidation defect.
- `...-kernel-v2`: requesting the peer's ifindex across namespaces was silently
  ignored by Linux; the fixture now creates the local end inside the robot and
  verifies the requested index. No host interface is touched.
- `...-production-v3` / `...-race-v3`: rebuilt lease recovery was tested against
  the deliberately blackholed target. The harness now proves it with the second
  approved, reachable target while keeping the blackhole in place.
- `...-production-v4` / `...-race-v4`: storage was filled before CLI admission,
  so an earlier cache-open write failed before release; injection now occurs
  after real production admission. The foreign-state harness also aborted on
  ENODEV during legitimate reconstruction; its probe now reports the unavailable
  interface as a failed observation and continues within the original bound.

## CI scheduling correction

[CI 37433716347](https://github.com/timo-kang/vpnctl/actions/runs/37433716347)
failed the shared Go job: `internal/history` reached its cumulative 600s package
limit while `TestWireGuardLargeHistoryResponseIsExplicitlyTruncated` had been
running for only 6s. The new full apply race suite passed in that same job but
consumed 578.858s alongside history/controller work. There was no reported data
race or assertion failure in that log. The failed run and log are preserved.

The complete relayapply race package was moved to a dedicated runner, with its
original 10m package deadline. At this stage every other package remained in the
Go race job; subsequent serialization and history separation are recorded below;
no preparation, history, or controller test is removed, and no product/lease/
observation timeout is widened. The final CI verdict must come from the revised
commit, not the preceding locally passing subsets.

## Rebuild admission correction

That same CI passed all production rebuilding cases and all race crash, ENOSPC,
physical-recovery and foreign-state cases. Race capacity positions 0 and 3 failed
its unchanged 120s watchdog; position 7 passed. Their logs show forward progress
without ownership/budget failures, but each of 21 transitions rejoined the FIFO
behind two app waves, costing roughly 5–6s per transition. Both apps remained
live. The failed race artifact remains at
`/tmp/vpnctl-preparation-ci-37433716347-race`.

Supervision now permits at most two durable work units in the same original
750ms wall/BOOTTIME budget, after all lease maintenance. It attempts the second
only with at least 500ms remaining. Round-robin selection still advances for
each unit, and every mutation retains its own durable boundary and fresh checks.
A slow first unit yields its next turn; it cannot reset the shared clock or
extend the five-second maintenance budget. Regression tests cover both-unit
fairness, insufficient headroom and BOOTTIME exhaustion. The 120s convergence,
10s lease and 10s observation checks are unchanged.

Both complete local suites passed after that correction:
`/tmp/vpnctl-preparation-two-unit-production` and `...-two-unit-race`.
Capacity at positions 0/3/7 took 111.07s / 138.00s total; the sixteen crash
boundaries 18.04s / 33.47s; real ENOSPC 8.50s / 11.38s; all seven physical recovery
cases 100.42s / 102.76s; and all ten foreign-state cases 106.74s / 115.08s.
Full apply/CLI race also passed (203.044s / 44.855s), and the additional shared
BOOTTIME / parent-deadline headroom regressions passed independently. These are
local results; the revised full CI verdict is recorded in #171 / its PR.

## Approval-time fixture correction

The dedicated lifecycle job in
[CI 37436872347](https://github.com/timo-kang/vpnctl/actions/runs/37436872347)
finished in 244.161s but found a flaky new expiry/rearm fixture. The fake response
used `time.Now()` values retaining process-local monotonic components, unlike the
controller's UTC timestamps and actual JSON response. Duration arithmetic before
and after the UTC/JSON boundary could differ by nanoseconds and correctly fail
cache witness consistency validation. A standalone clock-read diagnostic
reproduced a 10ns discrepancy without changing any host clock; repeated original
expiry tests reproduced the cache error locally.

The fixture now uses controller-style UTC timestamps, and its shared fake API
performs a JSON round trip. Production approval validation and expiry thresholds
are unchanged. Twenty repetitions of all three expiry/rearm stages passed
(60 scenarios, 98.174s), and the existing observation-expiry case passed ten
repetitions (22.448s). Original failing logs are retained at
`/tmp/vpnctl-preparation-ci-37436872347-lifecycle.log` and
`/tmp/vpnctl-preparation-expiry-before-utc.log`; corrected runs are
`...-expiry-after-utc.log` and `...-observation-wire-time.log`.
That CI also passed the common Go race/vet/build job and both complete rebuilding
profiles. All detailed fault reports were complete. The race capacity repair
intervals were 63.71–68.49s at healthy positions 0/3/7, with maximum fresh
observation gap 6.868s, peak 28 FDs and 85,384KiB RSS. Production intervals were
35.66–39.33s, maximum gap 4.685s, peak 29 FDs and 29,372KiB RSS. Raw artifacts are
`/tmp/vpnctl-preparation-ci-37436872347-{production,race}`. Those passing jobs do
not turn the overall run with the fixture failure into a pass.
The final revised-head CI result remains the merge gate.

## Shared-runner admission contention

[CI 37439814898](https://github.com/timo-kang/vpnctl/actions/runs/37439814898)
passed the corrected complete candidate lifecycle job, but the common Go race
job failed `TestAdminVariableMeshConcurrentMutationsAndRestart/nodes_253`.
One of eight concurrent admin requests reached the existing 2s admission limit
and correctly received 503 with `operation not started`. The integrity test
then correctly reported one unremoved node after restart; it did not silently
retry or accept the incomplete population. The controller and history packages
were running concurrently and took 434.504s and 483.535s respectively. The raw
failure remains at `/tmp/vpnctl-preparation-ci-37439814898-go.log`.

The common race command now uses `-p 1`, isolating independent package workloads
on the shared runner. The full controller graph, eight concurrent clients,
package-local goroutines, overload tests, race instrumentation, production 2s
admission limit, and existing test/job deadlines are unchanged. All packages
still run; this change does not establish an overloaded production latency SLO.
The matching complete common-package race command passed locally with caching
disabled: controller 173.095s, history 175.298s, and all remaining packages
passed (`/tmp/vpnctl-preparation-serial-package-race.log`). Workflow YAML and
embedded Bash syntax checks passed. The revised full CI run remains required
before merge.

The same CI's production/race rebuilding jobs passed with all 28 detailed
completion reports valid; their artifacts are retained at
`/tmp/vpnctl-preparation-ci-37439814898-{production,race}`. Maximum capacity
observation gaps were 4.360s / 4.962s and peak worker RSS 29,628 / 85,764KiB,
within the unchanged 10s / 512MiB limits. These passing subsets do not override
the failed common job.

## Delayed-observer terminal identity correction

[CI 37442861237](https://github.com/timo-kang/vpnctl/actions/runs/37442861237)
found a real independent-app interruption during race `PreparationRecovery`.
After the old endpoint route was removed, rebuilding p00 allocated a new random
route metric. The separate app2 observer drained that creation notification
under its previous journal mapping, classified the OIF-less route as unknown,
and reset p01's confirmation. p01 remained reachable with a valid lease, but its
application was correctly quarantined because its observation generation had
changed. Earlier successful runs missed this ordering. The failure is preserved
in `/tmp/vpnctl-preparation-ci-37442861237-race` and the matching `.log`.

Preparation intent now durably retains the exact terminal table/metric/underlay
tuple, including the gap without an installed entry. For an unchanged binding,
reconstruction reuses that route metric while rotating installation alias/index.
Every new install still proves resources available, and all existing live
ownership checks remain. Observers continue to drain under their previous map;
unknown/foreign/retired tuples still invalidate globally. The bounded scope map
permits eight installed entries plus eight waiting intents, without increasing
the eight-installed-candidate limit. Unit regressions reproduce delayed event
consumption, missing-entry/reopen intervals, identity rotation, scope mismatch
rejection and explicit release retirement.

The same CI's serialized common Go job passed controller (354.096s) and history
(381.821s), then hit its cumulative 15m job limit. GitHub stopped that job; no
running experiment was manually canceled. History now runs on a separate runner
with the original 10m package deadline and the same exclusions already covered
by dedicated churn/byte-budget jobs. The common runner retains all other 34
packages except relayapply/history; full relayapply remains separate. There are
26 CI jobs, with no removed tests or extended deadlines. The stopped Go log is
`/tmp/vpnctl-preparation-ci-37442861237-go.log`.

After correction, the complete local production suite passed: capacity 111.27s,
crash 18.27s, ENOSPC 8.51s, recovery 100.37s and foreign-state preservation
108.71s. The race recovery suite passed three consecutive repetitions of all
seven physical changes (101.89s / 102.21s / 102.45s). Full affected-package race
passed, including relayapply 213.081s and CLI 43.571s. Focused event/intent
regressions, vet, YAML/Bash and diff checks also passed. Artifacts and logs are
`/tmp/vpnctl-preparation-stable-scope-production`,
`...-stable-scope-race-repeat`, `...-stable-scope-full-race.log` and
`...-stable-scope-regressions.log`. The complete race integration run is recorded
separately at `...-stable-scope-race`; its final result and the revised full CI
verdict must be confirmed in #171 / its PR before merge.

## Waiting-scope migration review

Final self-review found that returning a conflict for an old waiting intent's
scope overlapping a newly assigned catalog table could block the replan that
resolves that overlap. Ambiguous tables now receive no scoped-event exception;
their events remain global and normal ownership-checked rebuilding can continue.
A deterministic regression constructs the missing-entry/current-entry overlap,
checks conservative omission without an error, and checks restoration after
retiring the stale intent. It does not change approval, ownership or packet gates.

Focused race regressions passed (`/tmp/vpnctl-preparation-ambiguous-scope-race.log`),
then the complete relayapply/underlayevent race packages passed (207.427s / 1.163s)
in `...-migration-full-race.log`. The complete real-kernel race suite passed in
`/tmp/vpnctl-preparation-migration-race`: capacity 135.79s, crash 32.78s,
ENOSPC 11.33s, recovery 102.02s, foreign-state preservation 113.07s. All fourteen
detailed completion reports were valid. Final revised-head CI remains required.

## Qualification boundary

The recovery watchdog (60s after foreign-fault removal / 120s for underlay
reconstruction or concurrent load) is a test failure bound,
not a physical failover SLO. Process SIGKILL/restart is covered; host reboot or
suspend is not performed by this suite. A journal in another boot/network domain
continues to require explicit reconciliation. Controller approval and fresh
packet evidence remain necessary after rebuilding.

Actual NetworkManager hotspot, Netplan renderer, udev/EtherCAT coexistence, RF
hardware, more than eight paths/two target loops and operating SLOs remain
#22/#23/#24 work. Passing this issue does not close M3 or authorize deployment.
