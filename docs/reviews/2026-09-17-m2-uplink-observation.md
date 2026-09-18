# M2 #16 staged uplink observation review

Scope: opt-in robot → server observations, not network control. Base main:
`0b2cd43` (#54). Review includes collection/lifecycle, truthful diagnosis,
identity/admission, persistence/retry/retention, rootless behavior and deployment
reuse. The implementation and its tests were reviewed together.

## Findings addressed

1. **High — registration-only collection misses the outage it is meant to explain.**
   The observer is owned above the node session, starts before registration and
   survives retries/tunnel repair. It has its own credential-aware client and is
   canceled/joined independently of heartbeat and credential maintenance.
2. **High — target success can pollute peer quality or imply a proven relay.**
   Targets have their own bounded identity/protocol series and snapshots. They are
   never registered as peers and never feed peer quality. Expected relay labels
   are separate from actual longest-prefix WG peer fingerprint, endpoint and
   fwmark-based outer route lookup. The docs identify lookup/ECMP/app-mark limits.
3. **High — partial or ambiguous failures can become false diagnoses.**
   Missing tools/permissions are unknown. Controller reachability is independent
   of server availability. Relay success plus a server timeout identifies the
   remaining endpoint path, not a proven server-process failure. A target reached
   through an unlisted link prevents a false `no_uplink` conclusion.
4. **High — unsupported route lookup on minimal deployment images.**
   Real Debian sandbox testing caught `ipproto tcp` failing without the protocol
   name database. The implementation uses numeric 6/17; two-underlay mark-routing
   tests then verified the observed transport changes with actual kernel rules.
5. **High — unrecoverable samples can block uploads indefinitely.**
   Exact body/ID retries preserve deduplication. The 64-entry queue drops/counts
   oldest entries; permanent 400/409/413 responses are counted and skipped.
   Authentication, temporary network and capacity failures remain retryable.
   Pending loss on stop/config replacement is logged and explicitly documented.
6. **High — new history must not hold security transitions behind long reads.**
   The new query follows the existing authenticate/query/reauthenticate pattern.
   A regression test removes the caller during a blocked query, verifies removal
   does not wait for that query, and verifies publication returns 403.
7. **Medium — private server TLS and local trust failure semantics.**
   TLS probes validate names and CA trust, support an optional reread private CA
   file and never disable verification. Missing/invalid local trust is unknown;
   untrusted server handshakes fail. Bounded regular-file reads reject FIFOs.
8. **Medium — empty gateway lists and optional-tool noise.**
   Gateway state now distinguishes absent default routes from unavailable
   collection. Missing optional modem/resolver binaries do not emit repetitive
   command warnings; their unknown states remain in each snapshot.
9. **High — actual WireGuard peer loss must not look like collection uncertainty.**
   Removing the configured peer makes Linux return `ENOKEY`; classify it as
   unavailable, and verify peer removal/restoration in all three kernel fault
   cycles in addition to responder-only outages.
10. **Medium — combined storage can exceed previous capacity assumptions.**
   Schema 2 shares the 1GiB database/WAL budgets, adds per-node/global snapshot and
   target-series quotas, and updates backup/restore/migration. Capacity failures
   do not publish status or acknowledge data. Retention removes both datasets in
   bounded transactions. Full scale now includes both datasets together.

## Verification

- Full Go race suite, vet and build; targeted TLS/UDP/cancellation/queue/identity/
  history migration/backup/retention/quota tests.
- `TestNetns_UplinkDiagnosis`: real shipped CLI, kernel WG, two underlays,
  separate server namespace, marked transport selection, controller-only outage,
  service outage, relay responder outage, route loss, absent LTE and total uplink
  loss. Three failure/recovery cycles.
- Existing complete 1/3/8/32-node suite with automatic collection on every node,
  mTLS target-history CLI reads, certificate renewal/revocation/rotation,
  process restart, forwarding/return-route/firewall/uplink/NAT faults. Two-CPU
  production-binary profile; independent Go race validation.
- Combined full scale: 3,870,720 peer probes plus 322,560 uplink snapshots with
  four targets each. Initial local run: 638,902,272-byte database, 24h peer query
  0.440s, seven-day peer query 3.095s, seven-day target query 0.053s, combined
  expiration 20.151s. The CI fixture runs the same budgets on every PR/main.

Final PR/main CI evidence is recorded on the linked issue/PR; these measurements
are local runs and are not a claim about modem hardware or production capacity.

## Remaining boundaries

#16 delivers observable state and sampled reachability. #17 still owns structured
change events, alert rules and long-running monitor retention; #18 owns the
backend/responder support matrix. M2 overall gate #19 remains open.

There is no durable robot-side spool, packet-level path proof, RF/hardware modem
qualification, mTLS application-login probe, automatic uplink/relay switching or
prediction in this change. The reusable sandbox/deployment contracts and these
boundaries are in `docs/validation/uplink-observation.md`.
