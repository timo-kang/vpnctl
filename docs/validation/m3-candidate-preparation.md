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
