# Robot → server uplink observations (schema 1)

The unit of success is a configured server endpoint reached from the robot.
VPN is one possible route. No robot motion command, modem activation, link change,
route change or relay selection is performed by this observer.

## Enable automatic collection

Add this section under the existing **node** configuration. List the complete
underlay set whose absence should mean `no_uplink`; interfaces need not exist.
Choose stable, non-sensitive target IDs. Change the ID when an endpoint's meaning
changes, otherwise its old and new results intentionally share one history series.

```yaml
node:
  # Existing name/controller/WireGuard/PKI settings remain required.
  uplink_observation:
    interval_sec: 60
    timeout_ms: 1000
    links:
      - {id: wired, interface: eth0, kind: ethernet}
      - {id: wifi, interface: wlan0, kind: wifi}
      - {id: cellular, interface: wwan0, kind: lte, modem: "0"}
    controller_probe:
      host: 192.0.2.10
      port: 8443
      protocol: tcp
    targets:
      - id: robot-server
        host: 198.18.0.2
        port: 443
        protocol: tls
        ca_file: /etc/vpnctl/server-ca.pem
        interface: wg0
        relay_id: primary
        relay_probe:
          host: 10.77.0.1
          port: 51900
          protocol: udp-echo
```

`uplink_observation` absent disables the worker. Defaults are 60 seconds and
1 second per probe. Limits: 30..3600 seconds, 100..5000ms, 1..8 links, 1..4 targets.
`node serve` collects before registration and keeps its worker and upload queue
across registration failures and tunnel recovery. Config changes are picked up
at the existing serve retry boundary; restart to apply changes immediately.
`node run` also owns a worker for its process lifetime. Standalone `monitor` does
not upload these observations.

Collection starts immediately, then waits the configured interval **after** a
cycle and its bounded uploads finish. Link and target tasks run concurrently,
with at most 12 tasks. Each link gets up to three probe timeouts for collection
and one for its controller probe; each target has separate relay, service and
transport observation budgets. The worker is independent of heartbeat and
credential renewal and is canceled and joined on shutdown.

The controller probe is **explicit**: select an endpoint reachable on the
underlays being evaluated. It does not silently reinterpret an API URL reachable
only through VPN as an underlay endpoint. TCP success establishes listening-port
reachability, not controller authentication or general Internet availability.
Each per-link controller socket is bound to that interface, including its route
lookup. A bind permission error is unknown; it never falls back to another link.

## Probe and collector meanings

- `tcp`: TCP connection established; latency is connection duration.
- `tls`: connection plus TLS handshake, hostname/IP and CA validation. System
  trust is the default; optional `ca_file` supplies a private trust bundle. It is
  reread on every probe so replacement is effective without restart. No skip
  verification option exists. This probe does not present client credentials or
  assert application authorization/health; choose TCP for reachability to mTLS
  services, or an appropriate authenticated application probe in the app layer.
- `udp-echo`: a fresh unpredictable `vpnctl-echo:` token must be returned exactly.
  Requires a vpnctl echo responder or compatible echo service, not arbitrary UDP.
- DNS resolves through the host resolver. Up to four returned addresses are
  attempted within the overall probe deadline. Success on any is success;
  exhausting a truncated address set is unknown. The recorded route belongs to
  the successful address, or the most advanced observed failed attempt. Socket
  latency excludes DNS and route lookup; TLS includes handshake.
- Ethernet/Wi-Fi: Linux interface presence, administrative/carrier flags and IPs.
  Wi-Fi association identity/SSID and radio signal are intentionally not collected.
  Gateway addresses come from `ip -4/-6 -j route show default dev IFACE`; no gateway
  is required for a valid on-link network. `gateway_state` distinguishes absent default routes from unavailable tooling.
- DNS is per-link **configuration presence** from `resolvectl dns IFACE`, not a
  successful DNS query. Without systemd-resolved it is unknown; the global stub
  resolver file is not attributed to every interface.
- Optional LTE `modem` selects a numeric ModemManager index. Read-only
  `mmcli --list-modems/--modem --output-keyvalue` distinguishes `no_modem`,
  `modem_no_service`, `modem_no_data`, connected and unknown. Missing mmcli,
  inaccessible D-Bus or permission failure means `modem_collector_unavailable`.
  An independently working IP interface remains usable if modem inspection fails.
  Output keys/one-based list indices follow the upstream
  [ModemManager output implementation](https://raw.githubusercontent.com/linux-mobile-broadband/ModemManager/main/cli/mmcli-output.c).

Collectors and probers implement the small interfaces in `internal/uplink` and
can be replaced by an embedding application. No modem, root or resolvectl is
required for basic collection and unbound target probes. `ip` improves route
visibility. WireGuard peer/mark inspection and interface-bound probes may require
capabilities; missing privilege produces explicit unknown stages.

## Failure and path evidence

Every link has its own controller result; every target retains route, relay,
service and outer transport results. A controller failure does **not** imply
failure of an already established server path. A server timeout with a working
relay is `server_endpoint`: forwarding, firewall, return route and service faults
remain possible. `relay_tunnel` means its configured responder did not reply over
the expected interface, not proof of a broken WireGuard handshake.

`underlay.reason=no_uplink` means every **configured** link is known unusable.
Unknown collectors prevent this diagnosis. A successful target despite all listed
links being down changes the aggregate to `unknown/unlisted_uplink`.
`failure_stage` is the earliest observed failed stage for the target, not a
causal diagnosis. Independent stage results must still be inspected when the
service works (for example an unexpected interface or dead optional relay probe).

The target socket follows the current kernel route. Optional `interface` checks
that result against the operator's expectation; it does not force the target onto
that interface. Route evidence is an `ip route get` lookup with destination,
protocol and destination port. `ipproto` uses numeric protocol IDs and works on
minimal images without `/etc/protocols`.

Where WG inspection is permitted, the longest matching peer AllowedIP chooses a
peer; its current endpoint and interface fwmark are used for the outer route
lookup. `transport_route` identifies the selected underlay and gateway.
`relay_peer_fingerprint` is SHA-256 of that peer's textual public key.
`expected_relay_id` remains a configuration label, separate from this evidence.
Lookups are snapshots, not packet tracing: concurrent route changes, ECMP source
ports, application-specific marks and namespaces may give other traffic a
different path. M3 remains responsible for switching and policy verification.

## API, CLI, storage and loss bounds

```sh
vpnctl node diagnose --config robot.yaml
vpnctl node diagnose --config robot.yaml --submit
vpnctl fleet status --config robot.yaml --json
vpnctl fleet uplinks --config robot.yaml --node robot-01 --window 7d --json
```

`node diagnose` is a bounded, read-only, one-shot observation and emits JSON on
stdout; logging is on stderr. `--submit` explicitly uploads it. Node name is the
registered reporter identity. Target servers do not need peer registration.

- `POST /uplink-observations`: `{node_id, snapshot}` with the same node-bound mTLS
  authorization as other node writes. Maximum snapshot is 32KiB. An identical
  `(node_id, id)` retry is idempotent; different content returns 409. Invalid input
  returns 400; capacity/storage errors return 503 and are not acknowledged.
- `GET /fleet/status` retains schema 2 and adds optional `uplink_observation` per
  node. Peer quality is never synthesized from target or intermediate-stage data.
- `GET /fleet/uplinks?node_id=robot-01&window=7d&limit=100` returns schema 1,
  per-target/protocol summary over `(start,end]` and recent complete snapshots.
  Node is required. Limit is 1..1000; `truncated=true` explicitly indicates omitted
  old snapshots. Summaries still cover the entire window. Long queries execute
  outside the security admission lock and reauthenticate before publishing.
- Availability = successful / (successful + failed) observations. Unknown is
  counted separately, with null availability when nothing is measured. This is
  sampled reachability, not wall-clock uptime. Average latency uses successes only.
- Latest status becomes stale after three configured intervals or clock reversal.
  Old fields remain inspectable; `stale=true` is not current connectivity evidence.
- The node retains 64 unsent snapshots in memory, retries the exact body/ID, and
  sends at most four per cycle with a three-second request timeout. A full queue
  drops the oldest, increments cumulative `dropped` in subsequent snapshots and
  logs the loss. Permanent 400/409/413 rejections are dropped and counted so a
  malformed sample cannot block the queue; authentication/network/capacity errors
  remain retryable. Stop/config replacement discards pending memory and logs its
  count. **There is no disk spool or guaranteed outage capture across process
  death.** Missing sampling intervals are not converted into success or failure.
- Endpoints/CA paths, SSID, IMEI/IMSI, modem serials and raw command output are not
  uploaded. IPs, interface names and routes are visible in authenticated fleet
  APIs and CLI. These observations add no target/device Prometheus labels. The
  anonymous legacy status page does not include the detailed uplink payload.

Persistence uses the existing private `history.db`, transactionally migrated
from schema 1 to 2. The old peer tables and API contracts remain intact. Seven-day
retention and backup/restore include both datasets. `controller history backup`
requires the controller stopped; schema 1 backups migrate on restore, schema 2
cannot be opened by older binaries. Back up before upgrading; rollback uses the
old binary and its pre-upgrade backup, not an in-place downgrade.

Shared limits: 1GiB DB and 64MiB WAL backpressure watermark. In addition to existing
peer limits, uplink snapshots are capped at 400,000 globally / 20,160 per node,
128 reporter nodes, and 256 target/protocol identities globally / 16 per node
within retention. An accepted snapshot and its aggregates commit atomically.
Latest status uses detached memory; long queries share the existing eight-second
query budget. Retention deletes in bounded batches; startup maintenance budget
is 60 seconds for the combined datasets and canceled batches preserve progress.

The supported scale fixture combines 32 nodes, four targets, one-minute uplink
snapshots over seven days (322,560), plus 32 five-second peer streams (3,870,720).
Faster/larger collection must fit these limits; 32 nodes at 30 seconds exceed the
seven-day snapshot count budget. Storage size also depends on metadata size.
Capacity failure remains visible; retention is not silently shortened.

## Verification and sandbox reuse

```sh
go test -race ./...
VPNCTL_HISTORY_SCALE=1 go test ./internal/history -run '^TestHistoryScale$' -count=1 -v
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 ./scripts/test-netns.sh
```

`TestNetns_UplinkDiagnosis` executes the shipped `node diagnose` CLI in disposable
namespaces with a real WG relay and a separate target-only server. It tests two
physical uplinks, fwmark-selected transport, controller-only failure, service
stop, actual WireGuard peer removal, relay-responder failure, route removal, absent LTE, total uplink loss, and
three failure/recovery cycles. The 1/3/8/32-node PKI lifecycle suite enables the
actual automatic collector on every node and reads persisted target availability
through the shipped authenticated CLI while renewal/rotation/revocation and
relay forwarding/return-route/firewall/NAT faults run.

Fake collectors cover modem states, missing capabilities and ambiguity. Tests
also cover target/peer isolation, identity spoofing, revocation during queries,
queue overflow/recovery/cancellation, private CA validation/reload, mismatched UDP
replies, schema migration, deduplication, rollback, quotas, retention and backups.
No physical modem/RF or application authorization claim is made by these tests.
The external binary/artifact sandbox contract remains in
[tests/integration/README.md](../../tests/integration/README.md).
