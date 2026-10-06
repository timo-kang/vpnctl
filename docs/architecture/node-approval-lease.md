# Node approval lifetime and kernel leases

`node relay prepare --lease` creates a protected candidate whose traffic is
initially blocked. `node relay supervise` may open it only after a fresh accepted
controller request. This is preparation for application route activation (#157),
not activation itself: target reservation still reports `activated=false`, and
selection still reports `applied=false`. Legacy candidates prepared without
`--lease` retain their previous behavior and **must not be used by a future
application route actuator**. Changing protection requires release and prepare.

## Authority and clocks

Every node catalog/bind request captures realtime and CLOCK_BOOTTIME before the
RPC, with boot ID and network namespace device/inode. The accepted view's
controller, node, generation and immutable expiry are bound to this durable
witness in the private cache. Request latency consumes validity; completion time
does not start a new clock. A same-generation response retains its original
BOOTTIME deadline, even after restart or wall rollback. Across generations, a
deadline can grow only by the controller's increase in ExpiresAt. A different
boot/netns needs another authenticated request; the existing apply journal also
refuses a changed kernel domain. Nonzero time namespace offsets are unsupported.

The durable witness bounds continuation. It cannot reopen an expired kernel
lease. Fresh rearm proof exists only in the process which performed the accepted
refresh; opening a cache does not reconstruct it from timestamps. An expired gate
needs a request started within five seconds, and the first resulting deadline is
clipped to that request's five-second window. A successful short rearm is followed
by a conditional continuation without fresh proof.

The node uses the same proven guard as relay deployment: exact owned TC ingress
and egress eBPF filters, CLOCK_BOOTTIME, spinlocked generation compare/update,
and dedicated pinned objects. It adds the same nft realtime cutoff and staged
timeout set. Timer preparation cannot grant traffic; a delayed activation cannot
restart that timer. BOOTTIME deadlines are additionally clipped to the durable
node approval bound. Leases last at most ten seconds, often less because nft
seconds are rounded down and preparation reserves a safety margin.

SIGSTOP, SIGKILL, a blocked logger, storage failure or lock contention cannot keep
a protected interface usable indefinitely. Offline continuation requires an
already-live lease and still-valid cached authority. It stops at the earlier of
approval expiry and the last kernel lease deadline. Confirmed denial or ownership
failure causes independent best-effort blocking of both owned gates. If kernel
commands themselves cannot run, the existing lease expires autonomously. A
privileged external actor that deletes both guards is outside this guarantee;
vpnctl reports conflicts and does not claim ownership or recreate foreign state.

## Shared state and budgets

Prepare, release, recover, inspect, observation and supervision share the existing
private cache lock, namespace lock and digest-protected apply journal. The journal
records lease version 3 and the approval BOOTTIME upper bound before a longer
lease can be granted. A failed durable write prevents further grants in that
engine. Target quarantine entries are retained during candidate cleanup; expiry
must never release target quarantine and reopen the main/default fallback.

Node operations and supervision enter through a FIFO queue in the same private
cache, then acquire the existing cache and namespace locks. Admission is bounded
to ten seconds and never renews leases or observes approval. A process retains
its turn through contention and releases it with cache ownership; cancellation or
process death releases its descriptor-owned slot. Unsafe or full queues fail
closed. This applies to participating node binaries using the same cache, not
other caches or external network managers. See [capacity qualification](../validation/m3-observation-capacity.md).

After admission the supervisor retains a one-second controller request and a
five-second work budget (at most fifteen seconds including admission). It yields
between cycles and writes JSON after releasing locks. Other operations retain
their outer deadline and never replay a possibly completed mutation. Kernel
lease expiry remains independently bounded to ten seconds even if an owner is
stopped while holding the queue, cache or namespace lock.

Protected observation batches maintain all leases once before a common
three-second wave of at most eight concurrent TCP proofs (each at most two
seconds). Approval/cache, inventory, kernel checks and blocking stay serialized;
all workers join before ownership is released. The outer observation bound
remains twenty seconds, and maintenance has a five-second cap without TCP probes.
Timeouts and changed/inactive guards produce unknown evidence, never a healthy
path or a relaxed deadline. Public inventory sharing is scoped to one maintenance
pass or one observation wave; observation postchecks require a read begun after
their own TCP proof. Peer/address/guard/underlay reads and mutations remain live.
Capacity qualification includes 1/4/8 prepared candidates and two active targets.

## Deployment, stop, upgrade and recovery

Provision the dedicated bpffs with the existing
[`run-vpnctl\\x2dbpf.mount`](../../deploy/run-vpnctl%5Cx2dbpf.mount) procedure and
the kernel requirements documented in [relay leases](relay-lease.md). Provisioning
needs mount privileges; the ongoing service needs CAP_NET_ADMIN and CAP_BPF, not
CAP_SYS_ADMIN. Use the same UID and network namespace for all commands. The
[node supervisor template](../../deploy/vpnctl-node-relay-supervise.service) can
be copied into a separate deployment repository. It is not installed by tests or
by building vpnctl. Physical interfaces, NetworkManager, Netplan, udev, DNS, NAT
and default routes remain deployment-owned.

Example sequence on the intended deployment machine:

```sh
vpnctl node relay refresh --config /etc/vpnctl/node.yaml
vpnctl node relay prepare --config /etc/vpnctl/node.yaml --path-id p00 --probe-routes --lease
vpnctl node relay supervise --config /etc/vpnctl/node.yaml
# In another terminal, using the same identity/cache/netns:
vpnctl node relay inspect --config /etc/vpnctl/node.yaml
```

Repeat prepare for each approved candidate. The supervisor renews prepared
candidates; it does not create paths or repair drift. Stopping it leaves routes
and guards in place, and traffic stops by the last kernel deadline. An explicit
`release --path-id …` removes only exact owned resources. Use `recover` for a
pending prepare/release intent; it does not recreate an altered prepared path.
Resolve foreign conflicts with the responsible network owner before retrying.

Old caches without a witness remain readable but cannot protect a candidate
until a successful refresh. Old unprotected candidates require explicit release
and protected prepare. Older binaries intentionally reject the new cache/journal
fields. In-place downgrade is unsupported: keep the newer binary for cleanup and
recovery, or perform a controlled deployment rollback with complete, consistent
identity/cache/controller backups. Never strip fields, delete an initialized
journal, or regenerate private keys to force an old binary to accept the state.

## Evidence boundary

`scripts/test-m3-node-lease.sh` runs in disposable `--network none` containers with
owned netns/bpffs. It records real new/established TCP behavior, supervisor process
faults, offline continuation and expiry, storage/lock/output pressure, and foreign
peer/route/tc/nft preservation. Unit tests cover request-start evidence, response
replay, restart, wall rollback and BOOTTIME discontinuity. The shared relayguard
suite covers CAS replay/delayed proposals and kernel BPF enforcement.

No test suspends/reboots the development host or changes its wall clock. Reusing
the suspend-aware kernel guard and simulated clock tests is not a new physical
suspend-plus-wall-rollback qualification for a deployed robot. That boundary
requires a dedicated VM or another machine. Actual network manager coexistence,
automatic application route replacement, unbound payload/NAT verification and
last-known-good rollback remain the subsequent #22/#23 work.
