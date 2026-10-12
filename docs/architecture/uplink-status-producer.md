# Uplink observation producer (#226)

Implemented as an opt-in, in-process foundation in `internal/relayapply`.
`ReconcileTargetObserved` runs the existing target reconciliation and publishes
one immutable snapshot. There is no listener or new CLI flag in this slice;
Unix transport belongs to #227 and Go/Python reconnect consumers to #228.
Status describes network observations, not robot motion or application state.

## Lifetime and interpretation

Create one `UplinkPublisher` per fixed target for the lifetime of a future watch
process, outside its short-lived Engine/cache ownership. Use one reconciliation
writer, as required by Engine. Call `Unavailable` if admission/open fails; this
withdraws prior evidence and rejects results from already-running cycles. A
reader only loads a value copy and the local clock, without an Engine, cache
lock, kernel ownership lock, RPC or additional probe.

| Availability | Evidence required |
| --- | --- |
| `reachable` | Applied, durably committed active route and successful unbound TCP proof, with live approval and installation lease bounds. |
| `unreachable` | Fresh failed bound TCP observations for every policy-permitted candidate, with usable approval and guarded target. Unknown/stale/invalid candidates prevent this claim. |
| `blocked` | Newly read explicit identity denial or approval expiry. This does not assert installed kernel quarantine. |
| `unknown` | Incomplete confirmation, admission/error/cancellation, uncertain persistence, invalid evidence, or expired observation. |

All fresh observations expire to `unknown/stale`. A rollback records a transition
but remains unknown until a subsequent successful reconcile verifies the current
route. `session_continuity` is always `not_established`; a new TCP connect cannot
prove an existing application session survived. There is no prediction field.

The observation starts **before the complete reconciliation cycle**. The deadline
is that start plus the selector's MaxAge (1–30 seconds), capped by approval for
reachable/unreachable and also by both live installation-lease checks for
reachable. This conservative boundary includes collection/selection/apply time;
a slow successful operation may already have stale status when it completes.
Blocked observations have a separate 10-second observation budget, without
requiring or renewing an approval. These are evidence budgets, not outage SLOs.
Private lease metadata is lost on JSON serialization; CLI output cannot be
replayed into current reachable evidence.

## Wire fields and clocks

Snapshots have `schema_version: 1`, fixed `target_id`, random `producer_id`,
`revision`, `path_revision`, availability/freshness/reason, `clock_domain`, optional
`observed_boot_ns`, `valid_until_boot_ns`, `observed_age_ms`, `path_id`, and
`evidence`, plus `remaining_validity_ms` and `session_continuity`.
Counters and absolute nanosecond values are **decimal strings**, preserving
uint64 precision. Unknown age is omitted; a known zero age is zero.
Only a bounded reason allowlist and path ID escape; private route identity,
addresses, keys, witnesses, raw errors and inventories do not.

`clock_domain` is `v1:` followed by lowercase SHA-256 of the UTF-8 bytes
`vpnctl.uplink.clock.v1`, NUL, and the existing KernelDomain string
`<trimmed boot_id>:<netns st_dev decimal>:<netns st_ino decimal>`.
Both peers must independently verify this domain and zero MONOTONIC/BOOTTIME
time-namespace offsets. `LocalUplinkClock` reuses `relayguard.Now` for this check.
There is no wall-time fallback. Clock/domain failures and expired observations
are latched until newer live evidence arrives. BOOTTIME includes suspension.
Consumers must compare the absolute deadline at receipt and before use; neither
reading, queueing nor reconnecting starts a new TTL. Age/remaining milliseconds
are informational. Cross-host consumers require a different clock contract.

## Transition and compatibility rules

Journal `route_revision` advances at switch/quarantine intent and rollback
commit. The publisher privately compares this counter, installation owner and
active route tuple; `path_revision` advances when that identity changes. It
detects A→B→A, rollback, quarantine/reactivation and replacement installations,
including intervening changes not separately published. It counts observed
identity changes, not every physical packet-path event. Catalog generation and
wall-clock timestamps never serve as transition counters. Producer replacement
resets local revisions and requires consumer resynchronization. Expiry changes
the read-time freshness without inventing a new publication revision.

Revision saturation withdraws confidence without preventing safety quarantine.
The optional zero journal field preserves legacy serialization and checksum;
fresh committed verification upgrades a legacy active reservation. Older binaries
reject a nonzero new field through their strict decoder: a downgrade requires
the existing controlled release/migration procedure, not deleting the journal.

## Validation boundary

Deterministic tests cover expiry and delayed reads, suspend-sized clock jumps,
clock/domain failure and recovery, producer restart, stale/unknown candidates,
denial, cancellation, persistence uncertainty, JSON replay, uint64 precision,
concurrent readers, withdrawal races, route transitions and legacy journal load.
These prove the producer contract; they do not qualify Unix delivery, real app
reconnection, target hardware performance or a host suspend/reboot scenario.
Those follow in the transport/consumer slices using disposable environments.
