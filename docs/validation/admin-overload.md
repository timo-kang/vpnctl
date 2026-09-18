# Administrator overload and uncertain results (#60)

The former admin endpoint admitted every concurrent mutation and used ordinary
mutex queues. A client could time out before its operation started, then observe
a later mutation; retrying token creation could issue an additional credential.
The 253-request Actions failure in #60 exposed that missing contract. The existing
506-identity/63,756-edge integrity test remains a separate state-size test.

## Admission and execution contract

Authenticated local admin mutations share **one active slot and eight waiting
slots**, with a **two-second maximum admission wait**. These are fixed limits,
not a throughput promise. Queued requests hold neither the controller request
barrier nor a registry/PKI writer lock. Status, token listing and token result
lookup bypass this admission queue; their underlying storage/security locks still
apply. Malformed or unauthenticated requests cannot execute a mutation.

- Queue full or wait budget exceeded: HTTP 503, `Retry-After: 1`, explicit
  `operation not started`. Retry with bounded backoff using the same request ID.
- Request context canceled before admission: no mutation; HTTP 408 if the
  connection is still writable. A disconnected client may see a transport error.
- After acquiring the active slot: the operation finishes under the existing
  durability, rollback and security barriers even if the caller disconnects.
  Canceling a network request does not roll back an accepted filesystem change.
- A transport error, timeout or HTTP 500 after admission is an uncertain result,
  not evidence that the operation did not run. Client/server timeouts remain 30s.
  Shutdown still waits for accepted handlers before releasing state ownership.

The bound covers decoded mutation requests waiting to execute. It does not cap
all accepted Unix connections, slow body readers, or status requests. The existing
socket ownership/UID boundary, 1 MiB body limit and HTTP read/write timeouts remain.
This is local administrator overload protection, not an untrusted public API limit.

## Token creation and recovery

The Unix API requires `request_id` on `token.create` and `token.result`. The Go
client generates a random 128-bit ID before sending a create request if omitted;
it retains the ID in the response object and error text even if the response is
lost. For unattended use, supply and save your own ID before invoking the CLI.
IDs accept 1–128 ASCII letters, digits, hyphens and underscores; use no secrets.

```sh
vpnctl controller token create --config controller.yaml \
  --request-id enrollment-batch-42 --ttl 2h --single-use
vpnctl controller token result --config controller.yaml \
  --request-id enrollment-batch-42
# If the first response was lost, this retrieves the same creation result:
vpnctl controller token create --config controller.yaml \
  --request-id enrollment-batch-42 --ttl 2h --single-use
```

The request ID and parsed TTL/single-use options are persisted in the same atomic
token record. The same ID/options return the original token across concurrent
store instances and restart. Different options return HTTP 409. Expired, consumed
and revoked tokens are also returned unchanged: retry never grants fresh access
or resets expiry/use/revocation. `token result` returns the full record as JSON,
including those timestamps/counters. Retried creation and result lookup sync the
containing directory before confirming a previously uncertain rename.

A lookup's HTTP 404 means no matching committed record was found at that point.
It does not prove an already accepted operation cannot commit later. Retry create
with the **same ID and options** to reconcile. Never switch to a fresh ID just
because of a timeout. Request IDs are retained for as long as token history is
retained; restoring an older backup also restores its older idempotency history.
Old binaries must not overwrite this richer token store. Existing legacy/v1
records load normally; update controller and admin CLI together because old raw
create requests without IDs receive 400.

Node removal and token revocation retain their existing idempotent durable retry
behavior. CA transitions use `pki.status` to reconcile phase/generation after an
uncertain response; they are not blindly retried as a new rotation. Token result
lookup is not a universal asynchronous job journal.

## Diagnostics and verification

`vpnctl_admin_admission_total{result}` counts `accepted`, `overload`, `canceled`.
`vpnctl_controller_stage_seconds{operation="admin_mutation",stage=...}` records
`admission_wait` and `execution`. Execution includes security/storage waits and
response serialization; admission duration includes immediate rejection. Metrics
use fixed labels, never token values, request IDs or identities. Audit outcomes
include overload/canceled alongside existing success/failure. Token values remain
redacted from audit logs.

Tests cover full queues, the two-second admission bound, cancellation releasing
capacity, canceled waiters never writing later, accepted client disconnects,
recovery after controller restart, concurrent duplicate creation, changed options,
consumed/revoked results, ENOSPC/EIO-style before/after replacement failures, and
actual separate CLI processes. During blocked token persistence and a full queue,
32 overload requests explicitly reject while 32 mTLS fleet reads, one registration
heartbeat and an eligible certificate renewal complete within one second.
Destructive removal/revocation/CA operations intentionally retain their global
security barrier; this read SLO test does not claim isolation during those barriers.

Local non-race Unix HTTP bursts ran three times per size under process CPU affinity
(one or two logical CPUs, including client and controller). This differs from the
network sandbox's cgroup CPU quota. Every success matched one additional committed
token record; every other response was an explicit 503, with no unexpected errors.

| CPU affinity | Concurrent requests | Successes per run | Explicit 503 per run | Worst response across 3 runs |
|---|---:|---:|---:|---:|
| 1 CPU | 1 | 1 | 0 | 2.58 ms |
| 1 CPU | 8 | 8 | 0 | 16.01 ms |
| 1 CPU | 32 | 9–11 | 21–23 | 19.08 ms |
| 1 CPU | 253 | 10–253 | 0–243 | 538.65 ms |
| 2 CPUs | 1 | 1 | 0 | 1.23 ms |
| 2 CPUs | 8 | 8 | 0 | 8.65 ms |
| 2 CPUs | 32 | 9 | 23 | 14.50 ms |
| 2 CPUs | 253 | 14–17 | 236–239 | 37.60 ms |

Admission overlap depends on scheduling and write time, so even 253 clients can
serialize enough to all succeed in one run. The invariant is bounded queued work,
not a fixed rejection percentage. These short local bursts do not establish
production sustained throughput, a disk latency ceiling, or a deployment SLO.

```sh
go test -race ./...
go test -race ./internal/pki ./internal/controller ./cmd/vpnctl \
  -run 'Test(TokenCreation|TokenRequest|AdminAdmission|AdminToken|AdminOverload|AdminCLI)' -count=3
go vet ./...
go test -c -o /tmp/vpnctl-admin-load.test ./internal/controller
# Select CPU IDs permitted by the host's affinity mask:
taskset -c 0 /tmp/vpnctl-admin-load.test -test.run '^TestAdminOverloadVariableConcurrency$' -test.v -test.count=3
taskset -c 0,1 /tmp/vpnctl-admin-load.test -test.run '^TestAdminOverloadVariableConcurrency$' -test.v -test.count=3
```
