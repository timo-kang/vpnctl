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

7. Scenario review found that a controller WG peer can be absent from the robot
   registry, and its AllowedIPs can name the routed uplink server rather than
   its own VPN address. Native peers now retain their full WG key without an
   invented node ID/address. Registered WG counters bind by public key and
   captured registry epoch/IP, independently of probe destination binding.
   Real uplink-only integration asserts both the native controller key and the
   registered robot key are retained.

Verification results and CI links are recorded in the PR and issue #88. The
operating contract is [wireguard-observations.md](../validation/wireguard-observations.md).
Do not turn namespace/model success into a 24-hour soak, hardware reboot or
multi-underlay transition claim. Those remain separately gated in #19 and M3.

Local evidence before final CI:

- Complete general race suite passed; controller 179.071s and history 486.846s
  with the original per-ingest quota fixture. The fixture was then changed to
  seed valid retained rows in one transaction while keeping real capacity-edge
  ingests; the focused WG history race suite passed in 31.383s.
- Final-head focused race covered history, controller, monitor, peer source,
  CLI and HTML; history 30.198s, controller 4.868s. The later query admission
  test (removal/revocation during a held query) passed under race in 5.021s.
- Real compressed-payload budget: 334 large valid reports brought storage to
  the 128 MiB boundary. A new report reclaimed one old report, leaving
  134,217,430 bytes. Query/reopen/backup checks rejected an injected digest
  corruption. The race run completed in 42.865s.
- Real kernel monitor test passed in 13.74s including endpoint-less re-add,
  interface recreation and collector restart. Three-node PKI/uplink lifecycle,
  actual monitor delivery and controller history restart passed in 57.89s.
- A real schema-15 database created by the new code passed validation; the
  previous main binary (`c1f0443`) rejected it with `unsupported history database`.
- Final CI is tracked by [PR #90](https://github.com/timo-kang/vpnctl/pull/90).
  Only its final checked head is eligible for merge.

The final scenario correction was rerun in the real three-node uplink-only suite
(57.69s). The native controller WG key retained RX=251,068 / TX=120,900 bytes and
an observed handshake with empty registry node/address fields; the registered
robot peer retained its own node ID and 204 / 260 bytes. AllowedIPs in this setup
include the separate application server (198.18.0.2), demonstrating why that
route destination must not be attributed as the WG peer's VPN identity. Focused
race after this change passed (controller 5.075s, history 4.267s, monitor 1.021s).
