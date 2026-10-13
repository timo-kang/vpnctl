# Candidate probe ownership boundary

Candidate observation currently holds the node cache/FIFO and namespace ownership
through preparation, overlapping socket proofs, final checks and application.
Reducing that lifetime requires a separate transaction protocol. This change
makes the existing proof boundary explicit and rejects stale evidence before it
can affect a different journal owner. It does not release ownership or establish
a latency improvement.

## Current contract

`observePreparedGated` uses a private `targetProbeAttempt`:

1. Under the existing check gate, copy the candidate, nested pin and target
   prefixes. Verify the installed journal identity, approved target definition,
   current approval, live lease, kernel shape, inventory and underlay generation.
2. Run the bounded socket proof using copied inputs. The worker does not read
   an Engine or mutate the cache, journal or leases. Keep the actual proof
   completion time, including failed connection attempts.
3. Under the check gate, consume the attempt once. First compare the Engine
   lifetime, node/domain and installed entry fingerprint. Then perform the
   existing live kernel, inventory, approval, lease and underlay checks.

Identity comparison must precede `checkLease`: that helper can block a lease on
failure. A stale ticket must not use that side effect against another owner.
The wave's inventory checker is bound to its Engine; it cannot become a new
Engine's inventory snapshot through context reuse.

Preparation, running, completion and consumption are distinct states. Duplicate
execution/consumption does not produce health. Premature consumption permanently
invalidates a later completion. A canceled check gate discards the result without
accessing Engine state. Both the original context cancellation and deadline bind
postcheck work, even if its phase context has a longer lifetime. Finishing never
refreshes the proof's `ObservedAt` timestamp.

The attempt is private process memory, not a serialized decision or an authority
accepted from callers. It cannot resume on another Engine, even if that Engine
loads an identical journal, and cannot be consumed after `Engine.Close`.
`Close` must still follow the existing ownership discipline: finish/join Engine
operations before closing it. This change does not make the entire Engine API
safe for concurrent close or use after close.

## Required before releasing ownership

A journal entry fingerprint alone does not cover an application target changing
A → B → A while a probe waits. A later release/resume protocol must identify the
target incarnation and mutation revision, reread the current journal after FIFO
admission, reject obsolete evidence, and avoid applying, quarantining or rolling
back from an old target snapshot. Cancellation or admission failure must not
block another actor's newly applied target.

That protocol must also release the cache admission ticket, preserve the original
wave/approval/BOOTTIME budgets, join socket workers, and prevent reuse of a closed
Engine's cache/save closures. There is no ownership-yield switch in this change.

## Verification

Tests model journal removal, recreation, pending state, generation, node/domain
changes, nested input mutation, target-definition mismatch, closed/reopened
Engine lifetimes, duplicate/early consumption and cancellation during postcheck.
A current lease failure must still invoke its existing fail-closed enforcement;
a stale identity must not invoke it. Existing wave ordering, overlap, connect
limits and cancellation tests remain applicable.

The journal-change tests deliberately model the proposed future handoff boundary.
They do not imply that another supported actor can change a journal while the
current production ownership lock is held. Performance qualification belongs to
the later implementation that actually changes that lock lifetime.
