# #88 implementation self-review

Scope: real WireGuard collection, bounded authenticated delivery and persistence,
reset-aware derived values, operator output and reproducible verification.

Findings fixed during implementation:

1. Endpoint-less peers were silently excluded. They now remain in kernel state;
   probe eligibility and measured transport counters are separate. Missing
   AllowedIPs normalize to an absent address; distinct public keys avoid empty-IP
   metric collisions and missing measurements remain NaN.
2. A reset observed between minute-spaced central samples could be hidden after
   counters grew again. Local counter/handshake/time discontinuities now advance
   the generation carried by later reports. The polling blind spot for entirely
   unobserved resets is explicitly inferred, never described as proved continuity.
3. Registering a report with only the remote peer binding could attribute another
   local WG interface to the reporter. Both registry bindings are captured and
   validated, and the observed local WG public key is checked before enqueue.
4. Count-limited history could still decode/return excessive data. Raw decode,
   snapshot JSON and fleet overview have independent budgets with explicit
   truncation. Reclaimed last records also remove their published live cache.
5. Reset/failure values and JSON integer precision could be mistaken for normal
   zero or wrap into large deltas. Unknown values are null/NaN, counters are
   decimal strings, integer subtraction precedes float conversion, and generation,
   clock/gap/reset/skew cases suppress inferred rates.
6. General race verification exposed an existing UDP flood fixture that treated
   loss of one echo as a blocked STUN consumer. It now permits retransmission
   within the unchanged one-second total budget; a blocked reader still fails.
   This changes the assertion, not the production direct protocol.

Verification results and CI links are recorded in the PR and issue #88. The
operating contract is [wireguard-observations.md](../validation/wireguard-observations.md).
Do not turn namespace/model success into a 24-hour soak, hardware reboot or
multi-underlay transition claim. Those remain separately gated in #19 and M3.
