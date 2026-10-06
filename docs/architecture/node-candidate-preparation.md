# Durable node candidate preparation

`node relay prepare --app-routes --auto-rebuild` explicitly requests continued
preparation of one approved path. The command returns `scheduled`; supervision
performs kernel work. Existing manual preparation stays manual. Repeating an
enabled request is idempotent and cannot change its controller identity. An
existing journaled application candidate can be explicitly opted in. Source-only
or unprotected candidates must first be released using the existing workflow.

## Consent and installed ownership

The private apply journal contains at most eight `preparations`, independently
of its installed `entries`. Each intent pins a controller ID and random revision.
The cache also holds `prepare-<sha256(path_id)>`, containing that exact revision.
This is local operational consent, not authority from the controller. Neither
file alone authorizes creation, lease activation or an application route.

Opt-in writes the journal before consent. Release unlinks consent and syncs the
cache directory before changing the journal or deleting kernel resources. This
does not allocate a replacement file. If a later journal rewrite fails with
ENOSPC, the old intent remains disabled after reopening. Supervision blocks and
cleans that disabled entry; it never reconstructs it. If the release journal was
committed, `recover` can finish its explicit cleanup. A failure before cache admission, or a failed unlink or directory
sync, is an uncommitted release and returns an error. Do not claim successful
opt-out from that error. Missing/unsafe consent cannot grant or continue a lease
for a managed candidate. Consent files, journal, keys and approval cache belong
to one private cache and must be backed up together.

Uncertain writes stop mutation until the cache and journal are reopened. Kernel
lease expiry remains independent of storage and process progress. As before,
the journal is tied to the kernel boot/network namespace; moving it to another
domain requires explicit reconciliation, not automatic adoption.

## Incremental execution

Every supervisor admission refreshes when due and services all candidate leases
first. It then advances at most **two durable work units** within the **remaining
five second maintenance budget**. Both share a single **750 ms** wall/BOOTTIME
budget; a second unit starts only with at least **500 ms** remaining. Each unit
still repeats approval/inventory/ownership checks and persists its own boundary. No 60 second Prepare/Release transaction runs inside this loop.
The round-robin path cursor and exponential retry delays (1, 2, 4, 8, 16, 30
seconds of BOOTTIME) are durable. Healthy paths already checked by that admission
do not consume rebuild work. Slow or conflicting paths cannot take all turns.
Underlying blocked storage/syscalls can still stall a process; the kernel lease
closes independently, and a late result cannot complete preparation.

| Phase | Work and exit condition |
| --- | --- |
| `waiting` | Require current approved binding, configured underlay inventory and free owned resources; journal a new random owner before creation. |
| `preparing` | One of link, alias, terminal route, endpoint route, mark rule, address, WG configuration, closed guards/link-up, probe routes, device-bound probe rule per admission. |
| `ready` | Complete ownership/inventory/approval readback committed; candidate still needs a fresh authenticated response to open its lease. |
| `removing` | Block the candidate, quarantine each referencing target, then delete one exact owned resource per admission and verify absence. An already selected independent alternative is preserved. |

An add is recorded `in_flight` before mutation. Process death or an uncertain
completion causes cleanup of the original random owner, followed by a fresh
initially closed installation. Adds are never blindly replayed. Deletions are
idempotent and reinspect live ownership every turn. Fully prepared owners retain
strict alias/key checks during cleanup; they do not gain the permissive handling
needed for a crash between initial link creation and its alias assignment.

Each preparation step requires a fresh plan from the current cache and physical
inventory. Controller generation may advance only for the same current candidate
binding; inventory drift during preparation restarts owned cleanup. Revocation,
expiry, controller mismatch and unavailable inventory do not authorize creation.
Cleanup of owned residue requires no new communication authority. Reopening a
cache does not turn its persisted approval into an authenticated rearm response.
Completion does not open an app route: normal selection still requires two new
successful observations and a verified application probe. A new owner/index
changes the candidate fingerprint even when the physical tuple returns unchanged.

## Network manager coexistence and observations

Only explicitly configured underlays are considered. `source_ipv4` is a hard
constraint; missing LTE, down links and collector uncertainty retain their
distinct plan reasons. No DHCP, DNS, default route, NetworkManager profile,
Netplan file, udev rule, RF/gimbal or EtherCAT configuration is rewritten.
Foreign aliases/indexes, peers/PSKs, routes/rules and nft/tc state are preserved
and reported as conflicts. A conflict schedules inspection with bounded backoff;
it does not authorize replacing the competing manager's configuration.

Target inspection recognizes exact owned **device-bound** probe routes/rules
through preparing/removing phases. This prevents a closed rebuilding candidate
from being mistaken for an unrelated bypass that quarantines healthy apps.
Source-only and altered rules remain conflicts. This exception grants no lease
or candidate eligibility.

The event monitor receives exact terminal-route tuples from the locked apply
journal: table, random metric, and underlay ID. Only the canonical protocol 186
unreachable default with that exact tuple can invalidate its own underlay alone.
Other OIF-less routes, unknown attributes, foreign metrics/tables and shared
nexthop events still invalidate all underlays. Queued events are drained under
the previous mapping before retiring it. This avoids interrupting an independent
app merely because an owned candidate's terminal guard is removed/recreated.
Packet/approval/ownership verification is still required after any event.

`inspect.preparations` and `supervise.preparation.preparations` expose consent,
revision, phase/step, interrupted work, retry BOOTTIME, last reason, previous and
current owner/pin/approval generation, and event generation. These fields are
diagnostics; public serialized output cannot be replayed as mutation authority.
Use the separate kernel lease and target application results for readiness.

## Deployment and validation

```sh
vpnctl node relay prepare --config node.yaml --path-id p00 --app-routes --auto-rebuild
vpnctl node relay supervise --config node.yaml
# After candidate readiness, use the normal target reserve/reconcile workflow.
vpnctl node relay release --config node.yaml --path-id p00
```

The existing node supervisor and target service templates can be reused by a
deployment repository. The new journal fields require this binary; older readers
reject them. Explicitly release managed candidates and reconcile their cleanup
with this binary before downgrade. Do not delete the journal/consent to bypass an
ownership conflict, and do not make service shutdown perform automatic release.

Run `scripts/test-m3-preparation.sh` for real source/gateway/link/index changes,
stepwise SIGKILL recovery and rebuilding alongside eight candidates/two apps.
Use `VPNCTL_RACE=1` for the race profile and `VPNCTL_TEST_BINARY` for an external
deployment binary. All mutations stay inside the runner's disposable container
and owned namespaces; no host suspend/reboot/clock/network action occurs.
The integration recovery deadline is a test bound, not a physical failover SLO.
Actual NM hotspot/Netplan renderer/udev/EtherCAT coexistence and field SLO remain
separate #23/#24 qualification work.
