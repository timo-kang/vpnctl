# Fresh underlay address inventory

The default Linux relay planner reads one interface and its addresses directly
from RTNETLINK. Route lookup still uses `ip route get`. The injected `ReadIP`
collector and non-Linux behavior are unchanged.

Each call opens a fresh socket in the caller's network namespace. RTM_GETLINK
resolves the exact name; RTM_GETADDR uses strict kernel filtering by its current
index. The normal collector still compares link identity, flags, operstate and
IPv4 selection inputs before and after endpoint route queries. There is no cache.

Missing links are `down/interface_absent` only after an explicit kernel ENODEV
response. Permission errors, malformed replies, interrupted or incomplete dumps,
missing strict-query support, and exceeding the existing address bound remain
unknown. IPv4 source selection retains scope, flags, preferred/valid lifetime,
ambiguity and configured-source checks. IPv6 records count toward the existing
address bound but do not affect IPv4 source selection. Unrelated devices no
longer consume the requested interface's serialized inventory budget.

Replies must have the expected sequence, destination port, message type and
kernel sender. Each datagram is kept below half the library's receive buffer;
total output and address counts are bounded. Framing is checked on every
attribute; duplicate identity/address attributes are rejected, while repeatable
padding is ignored. Cancellation closes the pollable socket and joins its close
callback before returning. No helper survives the namespace or ownership lock.

The implementation follows Linux's [address dump request validation and index
filter](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/devinet.c#L1635-L1770)
and preserves the repeatable padding emitted by [link
serialization](https://github.com/torvalds/linux/blob/v6.8/net/core/rtnetlink.c#L1189-L1396).
It requires NETLINK_GET_STRICT_CHK; kernels without it fail closed. Existing BPF
lease deployment requirements still apply.

## Verification and adoption

`./scripts/test-underlay-inventory.sh` runs a race-instrumented contract in a
fresh network-none container with only NET_ADMIN, one CPU, 256 MiB and no swap.
It compares the live result with iproute2, mutates addresses and link state,
renames/recreates the interface, adds unrelated interfaces, checks count bounds,
and verifies blocked-receive cancellation and descriptor recovery. It never
changes host interfaces or routes. Unit tests cover reply identity, incomplete
dumps, lifetimes, padding and duplicate fields. An independent regression proves
that default link/address collection does not execute the PATH's `ip` command.

This is a performance candidate until a prospective fixed comparison qualifies
it. Compare identical production binaries except for this change, at four and
eight candidates, using the existing two-app CPU isolation fixture. Preserve the
original freshness, payload and lease gates. Record robot cgroup CPU usage over
the steady observation window, completed cycles, cycle duration and fresh gaps.
A lower command count alone is insufficient. Reject a candidate that fails any
correctness gate or does not reduce the measured operating cost consistently.
Race capacity and production capacity remain separate profiles. Existing TCP
session continuity and application reconnect (#29) remain separate work.
