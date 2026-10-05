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

No failed run is hidden by rerunning into the same output directory. Older M2
24-hour evidence is unchanged; this work does not restart or replace it.

## Verdict boundary

Merge requires unit/race, vet/build and both kernel profiles on the PR's tested
revision. Production output proves TCP connect and WG transfer, not business
application health; payload/NAT are independent integration evidence. Existing
TCP session migration is not promised. Actual NetworkManager/Netplan/udev
coexistence, physical/VM power boundaries (#128/#135), multi-node operational
failover SLO and the rest of #23/M3 remain separate gates.
