# Explicit relay installation intent

`relay prepare` opts one approved endpoint into automatic installation by
`relay supervise`. It records the endpoint, local listen port, pinned controller
and relay public key/generation, and an absolute reference to an external private
key. It does not copy that key or grant traffic. Existing manual endpoints must
be explicitly released before enrollment; `relay apply` cannot bypass a recorded
intent. Repeating the identical request keeps its revision and resource count.
Changing the port, key reference, controller or key generation requires release
and a new explicit request.

```sh
vpnctl relay prepare --config /etc/vpnctl/relay.yaml --relay-id r0 \
  --endpoint-id ep0 --listen-port 51820 --key-generation 1 \
  --key-file /etc/vpnctl/private/relay.key --lock-wait 5s
vpnctl relay supervise --config /etc/vpnctl/relay.yaml --relay-id r0
```

The external key directory must be owned and mode 0700, and the regular file mode
0600 with no symlink or hardlink. Every creation unit safely reopens and checks the
key against the pinned public key. Diagnostics omit the reference and key contents.
The private `peers.json` journal now contains installation configuration as well
as public ownership metadata; protect and back it up as private configuration.

## Authority and failure boundaries

The supervisor first enforces current approval and maintains existing endpoint
leases. Rebuilding then advances at most one durable work unit within a 750ms
wall/BOOTTIME budget and the existing five-second cycle. It never gets the manual
CLI's independent cleanup deadline. The durable round-robin cursor prevents one
endpoint from monopolizing successful creation. Failures back off for 1, 2, 4, 8,
16, then 30 seconds in BOOTTIME; at most eight intents and endpoints are stored.

Every creation unit requires the current cycle's authenticated request-start
witness, current valid approval, matching controller/key generation, and local
key. Cached approval, a persisted timestamp, or a restarted process cannot
manufacture this witness. Each unit rereads authority before and after mutation.
A guard is created before the link and remains closed through configuration.
The six steps are guard, link, owner tag, WireGuard peers, link up, and peer routes.
Ownership is durable before creation and an in-flight marker before each add.
After a crash, the original owned partial resources are removed rather than
replaying an ambiguous add. Foreign resources are never adopted or overwritten.

Completed configuration is marked applied only after kernel and approval
readback. Rebuilding never calls lease renewal. `Maintain` subsequently needs a
fresh authenticated response to arm the initially closed nft/BOOTTIME guards.
Approval expiry or revocation removes the owned endpoint but preserves local
intent. A new matching approval can therefore restore it without an operator
running apply. New approval cannot silently rotate the pinned key or controller.
Manual installations retain their explicit-apply recovery behavior.

`relay release --endpoint-id ...` unlinks and fsyncs the separate revision consent
file before journal rewrites or kernel cleanup. The disabled intent stays in the
journal until ownership cleanup finishes: deleting it earlier could incorrectly
reinterpret a remaining endpoint as manual. Journal ENOSPC or a process crash
after accepted opt-out cannot restore that consent. A failed unlink/directory
sync is reported as an uncommitted release, never a successful opt-out.

Public `installations` reports distinguish consent, configuration phase, cursor,
attempt count, bounded retry deadline and blocking reason from actual endpoints
and `kernel_ready`. Neither an empty inventory nor configured peers prove uplink
reachability; the node's actual target probes and application traffic remain the
data-plane evidence.

## Restart and upgrade scope

Intent enrollment upgrades the deployment journal to version 2. Version 1 manual
journals remain readable; older binaries reject version 2, even after all intents
are released. No silent downgrade or deletion of initialized journal markers is
supported.

This increment supports process restarts in the same boot and network namespace.
The existing boot-ID/namespace identity check remains strict. A different boot
or namespace is explicitly blocked; old link indices, aliases, BOOTTIME deadlines
and pins cannot prove ownership there. Reboot bootstrap/migration requires a
separate reviewed contract and disposable-guest validation under #178. Do not
remove `peers.json` or its initialized marker to bypass this boundary.

## Validation

Fault tests cover each durable installation write, every interrupted kernel
step, invalid keys, key-generation changes, authority loss, fresh-witness checks,
consent revocation before failed cleanup, repeat enrollment and private-file
safety. The opt-in VM profiles are:

```sh
./scripts/test-manager-auto.sh --case manager-install-4 manager-install-8
```

They retain all 23 manual-mode coexistence/expiry scenarios and add five explicit
intent scenarios: enrollment, valid offline operation, real approval expiry,
offline relay-supervisor restart and recovery with a new authenticated approval.
The validator requires both relays to be empty/non-ready after expiry, the same
intent revisions after recovery, exactly one additional install attempt per
endpoint, and real TCP/UDP evidence. All manager/kernel changes run only inside
the guarded disposable VM. Functional passes do not qualify fleet p95, Wi-Fi RF,
EtherCAT real-time behavior, or cross-boot automatic recovery.
