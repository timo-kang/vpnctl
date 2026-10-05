# M3 application target actuation review (#159)

Base: main `503d052d4e01cf2cbe31dc1b81acc275302891c5` (PR #158).
Scope: ordinary local IPv4 mark-zero applications through protected relay candidates.
No host network, clock, suspend, reboot or mount changes. Local network mutations in
verification runs stay inside the invocation's disposable network-none container/netns.

## Review findings and fixes

1. **Existing TCP bypass (blocking):** after source selection, an ordinary app's
   established socket matched a source-only diagnostic rule ahead of quarantine.
   Added explicit `prepare --app-routes`, device-scoped probe rules and durable
   application fencing. Refuse every overlapping source-only candidate, including
   later re-preparation while the app target remains reserved. Real old/new unbound
   TCP must fail while all device-bound probes succeed; verified default fallback
   only returns after explicit target release.
2. **Reverse-path lookup incompatibility (blocking):** scoped probes failed with
   fixture rp_filter=2 (73 reverse-path drops in the diagnostic run). Preparation
   and live checks now require deployment-provisioned rp_filter=0 for namespace
   all/new-WG default or the existing owned WG. The product never writes sysctls.
   Deployment documentation explains preserving physical interfaces' individual
   policies and using a dedicated namespace when the shared policy cannot change.
3. **Interrupted transaction could keep renewed leases (blocking):** a surviving
   supervisor could otherwise extend a route whose actuator died before readback.
   Durable switching/releasing target references fence those candidate renewals;
   independent candidates continue. Recovery removes only journaled app routes,
   retains quarantine and needs new local proof to activate again.
4. **Candidate inventory rejected owned app routes (blocking):** the existing
   candidate contract forbade additional WG routes. Checks now recognize only
   exact active/pending tuples in the same journal with complete owned target
   reservation. Foreign routes still conflict. Candidate release quarantines every
   referring target before removing the WG device.
5. **Device rule cleanup order (blocking):** deleting WG first produces
   `oif_detached` and caused release to fail. Scoped rules are removed before WG,
   with transport guards retained until the socket is gone. Exact detached rules
   are recognized only during explicit release, never as ready probe evidence.
6. **Proposal time differed from commit time:** selector dwell now records actual
   verified application/rollback time. Rolled-back changes remain failed attempts
   (`applied=false`) even when the prior app path is live.
7. **Graceful watch termination:** a deliberate SIGTERM returned exit 1 through
   context cancellation. Selection/reconcile now finish their bounded cleanup and
   return normally on the signal context; real operation failures remain in JSON.

8. **Existing CI assumed cached approval survives every SIGKILL:** a crash during
   refresh correctly leaves `refresh_interrupted` metadata denial. The old control
   isolation test wrongly demanded `approval_valid=true` on offline restart.
   Supervision now exposes `approval_blocked_reason`; the restart assertion accepts
   only that specific additional safe outcome, still requiring unavailable refresh,
   blocked kernel, failed real TCP and no offline rearm. All other phases stay strict.

9. **Race CI exposed invalid test timing/admission assumptions:** a four-candidate
   observation took 2–3s, so a 2s recovery hold and 3s dwell could both elapse before
   the next complete observation. The fixture now spans multiple observations and
   checks actual committed route timestamps as well as the delayed decision.
   Eight-candidate supervision can also consume the one-second admission budget;
   `ownership_unavailable` correctly makes no claim that quarantine was installed.
   The slow-app fixture now watches until two completed negative/quarantined cycles,
   counts busy admissions separately and keeps sampling all eight kernel leases and
   second-app payload throughout, within a 90s fixture watchdog. Product lock,
   observation, mutation and lease deadlines are unchanged.

10. **Owned target hash collision (blocking, #161):** final node-lease race CI
    reproduced disjoint `app`/`app2` targets with the same priority 32551 for
    controller `7895f2cf50e105e75f4ecf1677eac81d`. The old allocator had no fallback.
    A bounded allocation slot now avoids only journal-owned table/priority
    collisions and is persisted before kernel changes. Existing target tuples
    never move; foreign kernel conflicts still fail. Slot zero preserves legacy
    JSON/digest encoding. Tests include the exact CI identity, 32 targets sharing
    one initial priority, interrupted reservation recovery, deletion/reopen
    stability, invalid slots and a forced real-kernel collision.

11. **The success fixture also assumed two lock admissions:** run `37337660581`
    reproduced one busy admission followed by one healthy confirming observation
    for the second app at eight candidates. The product correctly withheld
    activation. Successful integration transitions now run the operational watch
    loop with a bounded 90s fixture deadline, preserve every busy/negative result,
    and require at least two admitted cycles plus actual application proof before
    terminating normally. Negative one-shot exit checks remain in the suite.

12. **One-shot admission was not machine-readable:** the same run's node-lease
    race test encountered the one-second admission limit during the second target
    reservation. Prepare/inspect/recover/release and target commands now emit a
    blocked `ownership_unavailable` result before returning the admission error,
    without claiming kernel readiness or quarantine. The fixture retries only this
    pre-operation result inside its existing 65s watchdog and preserves every
    attempt; admitted operation failures, uncertain changes and foreign conflicts
    are not replayed. Node selection checks also use watch until all candidates
    have fresh confirmations. Held-cache CLI tests verify both deadline and output.

13. **The revised node fixture confused catalog and prepared population:** run
    `37341468321` passed both 16-case app profiles and the 4/8-candidate node
    cases, but the new readiness predicate incorrectly expected catalog count to
    equal prepared count in the one-candidate fixture (the catalog still has four
    paths). It now requires all prepared candidates to be confirmed, unprepared
    candidates to remain ineligible, and the selected path to be prepared. The
    complete 1/4/8 matrix in both profiles is rerun; product behavior is unchanged.

14. **Eight-path observation capacity (#162):** run `37344418818` passed the
    production app profile and both node profiles, but the 2 CPU app race profile
    could not confirm eight healthy paths within the unchanged 10s freshness
    window. Complete observations took 9.09–11.85s; the watch interval and admission
    added to the gap. TCP connects were mostly 1–3ms or less. Per-candidate full
    lease sweeps amplify kernel/inventory work. The selector correctly kept the
    target guarded. The app race profile now uses 4 CPU, while production keeps
    2 CPU; both retain 2 GiB, every assertion and all product deadlines. This is
    a validation resource profile, not a fix or qualification for the 2 CPU race
    capacity limit. #162 remains open for scheduling/cost improvement and mixed
    healthy/slow paths, before general operational availability can be claimed.

## Evidence and failure preservation

Local full production/race application suites passed, as did the legacy node
lease/target guard/selection kernel regression and the 176.59s control-isolation
regression. Full `go test -race ./...`, targeted race and vet/build also passed.
The final PR CI must pass both production and race profiles before merge. The
committed test suite exercises:

- Controller colocated/separate × candidates 1/4/8, independent relay recipients,
  two targets, real unbound nonce payload and server-observed relay NAT source.
- Underlay blackhole, relay uplink loss, all unavailable, recovery hold-down/dwell,
  manual pin, controller offline within valid approval, foreign peer preservation.
- Existing unbound TCP quarantine while all candidate probes are healthy; an
  independently verified main/default fallback stays blocked until explicit release.
- Real SIGKILL after app route delete/add, pending-intent fencing, unrelated live
  candidate and recovery without stale replay.
- Node-only short approval expiry and certificate revocation with independent
  relay approvals still live; outage cannot erase observed denial.
- Eight slow 2s probes with bounded negative results while all eight BOOTTIME
  leases and the second app's real payload continue.
- Foreign target route/rule/tc/nft/rp_filter and underlay address changes preserved.
  Address deletion also removes kernel routes using that source; restoration
  requires explicit candidate release/re-prepare, never silent adoption/repair.
- Unit fault injection at each of 16 delete/add boundaries for an eight-prefix
  switch, command failures before/after mutation, process-death model, durable
  commit before/after errors, cold restart, stale generation/fingerprint/deadline,
  policy-excluded LKG and source-only preparation fencing.

Local artifacts retained under `/tmp/vpnctl-app-*`:

| Run | Result / learning |
| --- | --- |
| `target-first`, `target-matrix` | Prototype unbound routes/payload passed; insufficient existing-socket isolation was subsequently found. |
| `device-probes`, `device-diagnostic` | Scoped probes failed under rp_filter=2; public rules/routes/counters retained. |
| `device-rpf`, `isolation` | Fixture setup failures: missing sysctl utility, then Docker's read-only proc/sys. Reused the existing private netns proc-mount pattern. |
| `isolation-v2`, `production` | Quarantine/SIGKILL/approval and later all six size placements passed; exposed detached-rule release defect and nft fixture syntax error. |
| `failover-slow` | Failover phases and slow probes succeeded; normal watcher SIGTERM incorrectly returned exit 1. |
| `foreign` | Ownership preservation held; address restoration alone did not rebuild deleted endpoint routes. Test now requires explicit re-preparation. |
| `final-production`, `final-race` | All phases except foreign-state passed; the intended explicit re-prepare call had not landed in the fixture. The corrected call is covered by `foreign-fixed` and `foreign-fixed-race`. |
| `verified-production`, `verified-race` | Corrected complete suites; immutable final CI results are recorded on the PR. |

PR #160 run `37327271704` is retained: app production/race exposed the missing
fixture re-preparation; control isolation exposed the interrupted-refresh test
assumption; M2 smoke failed before testing because the Go module proxy returned
an HTTP/2 INTERNAL_ERROR downloading `github.com/wlynxg/anet@v0.0.5`. No product
timeout or lease bound was enlarged to address these failures.

Run `37330628596` is also retained: production application validation passed;
race exposed the timing/admission assumptions above, without a data-race report.
Logs/artifacts are under `/tmp/vpnctl-pr160-app-race-second*`. All running jobs
were allowed to finish before publishing the follow-up change.

Run `37334104350` is retained: both application profiles passed, but node-lease
race found the real allocation defect #161 above. Its original logs/artifacts
are `/tmp/vpnctl-pr160-node-race-2cf1b09*`. The first new forced-collision fixture
was correctly refused for modifying bound path identities, then for skipping the
required disable revision before retirement. It now disables the old paths and
approves new path IDs for the new target set through the public API. No fixture
identity is rerolled to hide collisions.

The original app race log for `37337660581` is retained at
`/tmp/vpnctl-pr160-app-race-a28d908.log`; its other jobs are allowed to finish
before the admission-contract follow-up is pushed. No product deadline is changed.
The companion node admission log is `/tmp/vpnctl-pr160-node-race-a28d908.log`.

Run `37344418818` completed 21/22 checks. Failed app race logs/artifacts are
`/tmp/vpnctl-pr160-app-race-cb9be34*`; healthy 8-path observation gaps explain the
failure above. The complete run finished before the resource-profile change.
Go's [race detector documentation](https://go.dev/doc/articles/race_detector)
reports typical execution overhead of 2–20 times, and GitHub's
[public Ubuntu runner specification](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
provides 4 CPU for this public repository. Neither establishes a product minimum:
production/race capacity and mixed slow-path liveness remain tracked in #162.

No failed run is hidden by rerunning into the same output directory. Older M2
24-hour evidence is unchanged; this work does not restart or replace it.

## Verdict boundary

Merge requires unit/race, vet/build and both kernel profiles on the PR's tested
revision. Production output proves TCP connect and WG transfer, not business
application health; payload/NAT are independent integration evidence. Existing
TCP session migration is not promised. Actual NetworkManager/Netplan/udev
coexistence, physical/VM power boundaries (#128/#135), observation capacity (#162), multi-node operational
failover SLO and the rest of #23/M3 remain separate gates.
