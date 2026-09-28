# WireGuard handshake and transfer observations (#88)

`vpnctl monitor --interface wg0 --history-config node.yaml` observes the local
kernel and submits a separate WireGuard report to the controller. It does not
change robot behavior, routing, relay selection, or the agent heartbeat. A robot
may need VPN/relay connectivity to reach its server uplink because it has no
independent LTE uplink. Recent handshakes and growing counters do not establish
that target's availability or identify the actual relay/underlay.

## Collection and identity

- All kernel peers remain visible, including missing endpoints and missing
  AllowedIPs. Missing endpoints produce an unknown/unattempted echo probe, not
  network loss. WireGuard counters themselves remain valid observations.
- The entire eight-column peer dump is parsed or rejected. A zero kernel counter
  is a measured zero. A never-completed handshake is null with state `never`.
  File sources, failed commands, permission errors, malformed dumps and missing
  interfaces are unknown, with null counters/handshake. Private keys and PSKs
  from the dump are never included in observations or parser errors.
- Each sample carries collection time, full peer key, address, endpoint
  availability and a random generation. Process restart, interface index/public
  key change, observed peer removal/re-add, counter decrease, handshake
  regression, clock regression and a collection gap break continuity. A short
  reset observed between central reports advances the generation too.
- Interface index is read before and after collection. Two incarnations during
  that read reject the collection. The local interface public key must agree
  with the reporter's registered key before a measured report can be queued.
- Central binding captures both reporter and peer key/IP/registry epoch before
  enqueue. Renewal of a TLS certificate does not change this WG identity. The
  controller revalidates both bindings; removed, rebound and revoked reporters
  cannot silently relabel queued reports. Deleted peers disappear from live
  status; immutable history may still reference their previous identity.

Polling cannot prove the absence of an unobserved remove/re-add or reset between
two samples if the new counters have already overtaken the old values. Rate
validity is therefore **inferred**, with reason `polling_continuity_assumed`.
Never label this as a verified lifetime or route. Kernel reboot restarts the
collector process and therefore its generations.

## Numbers, windows and freshness

RX/TX absolutes and deltas are unsigned 64-bit **decimal JSON strings**, including
values above 2^53. Subtraction happens before conversion to floating-point rates.
`*_bytes_per_second` is bytes/second over the reported `interval_seconds`.
First sample, unknown input, generation change, reset, identical/reversed times,
clock-skewed handshake, or interval over 90 seconds yields null rate/delta.
A handshake older than the history retention remains a valid timestamp.

Local collection follows `--interval` (default 5 seconds); local freshness uses
`--quality-stale-after`. Central submissions are sampled at most once per minute,
and central views become stale at 90 seconds. The central rate describes its
actual minute-spaced interval, not the local five-second interval. Historical
views are evaluated at their own collection time. The first row in a queried
window may lack a predecessor and legitimately have an unknown rate.

## Delivery and persistence

WireGuard has an independent eight-report queue, separate from the 256-probe
queue. Reports are limited to 1 MiB JSON / 1,024 peers. Each immutable report has
a random stable ID; five attempts use three-second deadlines and 1/2/4/8-second
backoff. A lost acknowledgement cannot insert twice. An earlier new report or a
same-ID different body is rejected with 409. Retries never refresh timestamps or
bindings. Logical quota rejects are distinguished from transient SQLite/WAL/IO
errors. Shutdown drops the memory queue; there is no durable client spool.

The same private SQLite history database stores compressed reports with checksums.
The first successful WG upload atomically changes probe schema 5/6/7/8/9 to
15/16/17/18/19, preserving tiering/reclamation/jitter settings. Older binaries
refuse these versions. New binaries can read both families. Existing offline
feature migrations preserve the WG tables/version offset. Backup, inspect and
restore support the new versions; validation checks row/byte totals, node caps,
identity, timestamp, payload checksum, decompression limit and loss envelope.
Before rolling back the binary, restore a pre-WG backup while the controller is
stopped; changing only `user_version` is unsupported.

Budgets: maximum seven days, 10,080 reports per node, 400,000 fleet reports,
64 reporting nodes, 128 MiB compressed report payload; the existing shared 1 GiB
DB and 64 MiB WAL backpressure still apply. These are ceilings, not a guarantee
that every mesh can retain seven complete days at minute cadence. Full keys and
generations consume space. At pressure, oldest records are reclaimed to keep
current observation flowing, as requested by the operator. Up to 64 records may
be reclaimed atomically per upload; insufficient relief is a visible quota
rejection. Periodic expiry commits batches of 1,000, allowing cancellation and
resumption. Live entries for fully reclaimed nodes are dropped after commit.

Queries expose `storage.scope=fleet`, retained rows/compressed bytes, limits,
`evicted_reports`/`expired_reports` (decimal strings) and `loss_start`/`loss_end`.
This range is the envelope of all deletions since WG storage was enabled; it
is not a claim that every record in the interval or for the queried node was
deleted. Rate/counter continuity does not imply delivery completeness.

## Operator interfaces

- Local `/network/quality`: `wireguard[]` beside probe `peers[]`;
  `history.wireguard_delivery` shows delivered/pending/dropped/quota drops and
  `wireguard_interval_seconds` describes central sampling.
- `POST /monitor/wireguard`: mTLS report submission; no route/relay claim fields.
- `GET /fleet/status`: current, registered bindings only, under `wireguard`.
  The WG overview limits 256 peers per node and 2,048 peers per response and
  explicitly sets `views_truncated`. Per-node history supplies detailed reports.
- `GET /fleet/wireguard?node_id=robot&window=24h&limit=20`: 1..100 newest reports,
  maximum 168h window, eight-second bounded query, 8 MiB raw decode budget and
  4 MiB snapshot response budget. `truncated` means additional reports were
  omitted by count or bytes. Use a smaller window/limit for detailed inspection.
  Authentication is rechecked after the query; removing the subject during the
  query suppresses the buffered result.
- `vpnctl fleet wireguard --config node.yaml --node robot --window 24h --json`;
  text mode includes retention limits, loss envelope and collection reasons.
  Fleet status, monitor watch/TUI and controller HTML show the same units and
  validity; HTML escapes peer data and marks unobserved/truncated views.
- Local and controller Prometheus expose `vpnctl_wireguard_*` gauges. Missing or
  stale values are NaN, not zero. These are absolute **gauges**, not monotonic
  Prometheus counters: do not apply `rate()` to them. Float64 exposition can
  approximate values above 2^53; JSON strings are authoritative for exact bytes.
  `vpnctl_wireguard_delivery_total{result}` identifies bounded delivery outcomes.

## Verification and remaining gate

Unit/model tests cover uint64 precision/overflow, same/reversed clock, skew,
reset/wrap, generation and source boundaries. Integration tests cover all ten
schema combinations, offline upgrades, retry/conflict, backup/reopen/restore,
expiry, quota reclamation, cancellation, injected SQL failure and recovery,
1/3/8/32-peer meshes and large bounded queries. Actual mTLS tests include
certificate renewal without WG reset, binding changes, revocation, deletion and
acknowledgement loss through the real monitor reporter.

`./scripts/test-netns.sh` exercises the shipped CLI in isolated namespaces:
independent kernel transfer checks, real traffic/handshake, endpoint-less peer
re-add, interface removal, local JSON/Prometheus, real monitor→mTLS→SQLite→fleet
CLI and controller restart recovery. The existing PKI suite runs 1/3/8/32 nodes.
It emits only public observations; `wg dump` is never a result artifact.

M2 #19 and common observation parent #70 remain open until the mixed 24-hour
soak combines WG sampling, probe/raw/rollup history, events, renewal/rotation,
controller outages, changing mesh membership and bounded disk/WAL pressure on
representative deployment storage. Record both retained and reclaimed/dropped
populations; accelerated synthetic fixtures are not a production disk SLA or
lossless seven-day guarantee. M3 #21/#22/#24 still owns actual multi-relay and
LTE/Wi-Fi/Ethernet transition verdicts.
