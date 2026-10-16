# Candidate observation across ownership lifetimes

This is the ownership handoff contract used by `vpnctl node relay target`.
Plain `ObserveTarget` retains ownership. Reconciliation releases cache/FIFO and
namespace ownership during bounded candidate TCP proofs, then reloads state
before selecting or applying. It does not change thresholds or lease policy,
and no latency improvement is claimed.

## Identity and authority

A `targetProbeHandoff` wraps a one-use `targetProbeAttempt`; it does not weaken
that attempt's existing same-Engine contract. Preparation requires a protected
application candidate, a stable guarded/active target reservation and an active
underlay event monitor. It captures the complete entry fingerprint, target guard
(including random owner and saturated-safe route revision), preparation intent,
local consent, catalog and persisted approval witness. Transient authenticated
refresh evidence is never copied as permission to rearm a stopped lease.

A cache scope pins both the directory and `cache.lock` inodes with independent
read-only descriptors. They carry no flock or admission slot. Keeping the inodes
open prevents replacement/reuse from impersonating the old scope. Validation
requires that the issuing Store has closed, the new Store is a different
instance, and its held lock still matches both the pinned inode and current
`cache.lock` name. A new Engine over the original live Store is insufficient.

After fresh admission and journal loading, the consumer first checks these
identities, the old Engine's closure, node/kernel domain and current consent and
approval. Any mismatch consumes the result without invoking lease enforcement
against a replacement. Only an unchanged identity reaches the existing live
kernel, underlay inventory, approval, lease and event-generation checks. The
old Engine's shared inventory checker cannot serve the new Engine.

Public inventory sharing ends when observation returns, on success and failure.
Both the issuing and reacquired Engine restore their original command runners
before application, inspection, maintenance or mutation can proceed. Those later
checks must not reuse link, route or rule snapshots from the observation wave.

A current, owned lease found inactive still receives the existing blocking
behavior. Successful observation never renews/rearms a lease or authorizes a
route write. Selection, application proof, commit and rollback continue only on the fresh
Engine while its ownership remains held.

## Lifetime and worker discipline

The original context, cancellation and earliest deadline cover preparation,
probe, reentry and postcheck. A BOOTTIME bound also rejects suspend-spanning
expiry or a clock value before the original anchor. It is checked before starting
TCP work, before validation and after the final live checks. Neither reentry nor
consumption refreshes the socket proof's actual `ObservedAt`.

The original underlay monitor remains attached to the ticket. An absent monitor,
a lost stream or changed generation rejects the result. Supplying a replacement
monitor in the consumer context cannot erase the original event history.

The worker uses only copied probe inputs, context, clock and result storage. It
can start before the coordinator releases ownership and then continue without
reading the old Engine or Store. Completion is consumed atomically once;
premature consumption permanently invalidates late completion. `Close` cancels
work and releases identity pins, but the coordinator must still join workers.
The Engine as a whole does not become safe for concurrent mutation/Close.

## Diagnostic attribution

Fresh-Engine verification starts a `postcheck` diagnostic phase on the original
attempt context. This keeps the original lifetime and underlay event history
while attributing fresh commands to postcheck rather than the captured precheck
phase. The coordinator does not add a second phase around the same operation.
Phase durations remain summed work and are not additive wall-clock latency
when phases overlap. Earlier artifacts retain their original counters; the
attribution correction does not retroactively change their verdicts.

## Verification

Regression tests use real private cache files, journal reopening and FIFO
admission, with fake kernel operations. A blocked worker permits another owner
to enter and maintain candidate leases. Rejection coverage includes original
Store reuse, directory/lock replacement, target deletion/recreation/ABA and
revision saturation, entry/domain changes, approval and consent changes, missing
or restarted event streams, kernel/inventory drift, inactive leases, early and
duplicate consumption, cancellation, BOOTTIME expiry/rollback and final-check
expiry. Virtual time exercises the original context deadline without host power
or clock changes. Failure paths release and join test workers.

## Integration and remaining qualification

The target reconciliation coordinator releases Engine, Store and FIFO ownership
together, reacquires within the original reconciliation deadline, closes tickets
on failed admission, and joins every socket worker before proceeding. Route
transactions remain under fresh ownership. The full target digest deliberately
rejects even a concurrent verification-time update; tests cover that rejection.

Resource-constrained application continuity and scheduling remain qualification
work. Correct ownership transfer and isolated contract tests do not establish
faster recovery or a supported deployment capacity. Preserve failed VM evidence
and evaluate the complete unchanged fault/resource matrix before merging.
