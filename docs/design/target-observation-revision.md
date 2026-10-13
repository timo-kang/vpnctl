# Target observation and route revisions

A candidate proof is not permission to apply a decision to a different target
reservation. `ReconcileTarget` records an in-memory fence before observation and
checks the current target again before calling the selector. The fence binds the
current Engine lifetime, node, kernel domain and the complete target guard value.
A mismatch returns an unknown result with no reservation or activated/guarded
claim. It neither advances selector state nor applies, quarantines or rolls back
the replacement target after that check. The current target index and guard are
used when the check succeeds.

This remains an ownership-retaining boundary. It does not release the node FIFO,
cache or namespace lock, accept serialized fences, or resume on another Engine.
Candidate approval and live lease checks still run during observation. A genuinely
expired candidate lease must still be blocked even if an application target has
changed. This fence does not suppress that independent enforcement.

## Durable route history

`TargetGuard.route_revision` counts journaled route transitions. The revision
advances before switching or quarantining routes and on successful rollback. It
therefore distinguishes A → B → A even when the final active route is identical.
The reservation's random `Owner` distinguishes release and recreation. Neither
catalog generation nor a wall-clock timestamp is used as a mutation counter.
Steady verification does not increment the route revision; the in-memory fence
conservatively rejects a concurrent change to any guard field, including its
verification time.

This isolates the route-revision mechanism already developed for the application
uplink status work; it does not include that API, its publisher or its deployment.
Future integration should use the same field and helper, not introduce a second
route counter. The full target fence is private and has stricter lifetime checks
than an application status revision.

Zero remains the legacy encoding and is omitted from JSON, preserving old journal
checksums. Reading a legacy journal does not invent a transition. A fresh route
commit upgrades a zero revision to one. A nonzero field requires a reader that
understands it: older readers using strict field decoding reject that journal.
Retain the new reader for recovery; deleting the field or restoring an older
journal is not a supported downgrade procedure.

The counter saturates at `MaxUint64` instead of wrapping. Reconciliation at a
saturated revision performs safety quarantine and returns a recovery error before
probing or making a new decision. A switch at the final increment can still run
its bounded rollback; saturation never prevents quarantine. A saturated revision
must not become reusable authority in a future ownership handoff.

## Verification and remaining boundary

Tests cover durable forward/return transitions, rollback, quarantine, reopening,
legacy encoding and saturation. Modeled observation-time changes cover deletion,
recreation, A → B → A, route/prefix changes, verification time, node/domain changes
and current-index lookup. Discarded reports preserve confirmation history, the
applied selection and its dwell anchor. The current production locks prevent other supported
actors from making those modeled journal changes during observation.

Cross-Engine reacquisition, original admission/BOOTTIME budgets, joining workers,
fresh inventory collection and cancellation without stale route cleanup remain
required before ownership can be released. The application proof and rollback
also retain ownership; this change does not establish their safety across an
unlocked interval or demonstrate a latency improvement.
