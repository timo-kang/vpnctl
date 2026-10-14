# Target probe failure evidence

`target observe`, `target select`, and `target reconcile` can report an optional
`probe_failure` on a candidate observation. This diagnostic answers:

1. Which part of the candidate's TCP proof failed?
2. Was the failure a known error or a rejected evidence check?
3. Had the operation's context already ended at that failure boundary?

It does not grant reachability, approval, or application eligibility. Existing
`state`, `reason`, lease checks, confirmation counts, and deadlines remain the
decision contract. In particular, `probe_evidence_unavailable` still means the
candidate is `unknown`; a successful TCP connection alone is insufficient.

Example diagnostic (all values are fixed enums):

```json
{"probe_failure":{"stage":"counters_after","cause":"unavailable","context_state":"deadline_exceeded"}}
```

This example says that the final counter read failed and its context had reached
its deadline. It does not assert that the deadline caused the read failure. No
error text, command arguments, addresses, keys, or raw counters are copied into
this diagnostic.

| Field | Values |
| --- | --- |
| `stage` | `route_before`, `counters_before`, `connect`, `route_after`, `counters_after`, `transfer` |
| `cause` | `unavailable`, `canceled`, `deadline_exceeded`, `permission_denied`, `invalid_counters`, `missing_handshake`, `rx_not_advanced`, `tx_not_advanced`, `timeout`, `refused`, `unreachable` |
| `context_state` | `active`, `canceled`, `deadline_exceeded` |

The route and counter stages are relative to TCP establishment. A transfer
failure reports the first unsatisfied predicate in handshake, RX, TX order;
it does not imply that the remaining predicates passed. Missing or malformed
counter data cannot be treated as zero traffic. `context_state` is captured at
the failed operation, before the caller cancels its completed probe context.
For `connect`, it describes the dial context, including any narrower connection
deadline; the surrounding proof retains its original budget.

Successful probes and candidates rejected before probing have no diagnostic.
An absent field is also expected from older versions and uninstrumented probe
providers; it is not proof that no error occurred. Consumers should tolerate
future enum values as unknown diagnostics. The field is additive to schema v1.

If a later kernel, inventory, approval, lease, or underlay check rejects the
observation, its original `state`/`reason` takes precedence. Any probe failure
already captured remains diagnostic context, not a replacement decision.
The one-use probe attempt owns a copy of that diagnostic. A postcheck gate
cancellation can discard the observation while retaining its failure context;
starting a new attempt clears any diagnostic from an earlier observation.

To investigate a `guarded` result, correlate the candidate within the same
reconcile record and inspect `probe_failure`, `confirmation_gap_ns`, and the
existing diagnostics. Do not sum overlapping probe phase durations as wall time.
Do not infer CPU saturation, network packet loss, or a kernel defect solely from
`unknown` or a context deadline. Preserve the original failure before testing a
bounded hypothesis in an isolated environment.

This contract was added after issue #221: an 8-path, two-app baseline run lost
the healthy candidate's proof within the 10-second freshness budget. The old
record does not identify its failing substage. Adding this diagnostic does not
retroactively identify that cause or establish that the availability issue is
fixed.
