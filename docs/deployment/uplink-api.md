# Local uplink API (#227)

The opt-in API exposes observations for one application target from its existing
`node relay target reconcile --watch` process. It does not change robot motion,
network manager settings, or the application's reconnect policy. See the
[producer contract](../architecture/uplink-status-producer.md) for proof and
expiry semantics. Reconnect consumers and their payload matrix belong to #228.

## Provisioning and startup

Provision a **separate** runtime directory, for example `/run/vpnctl-uplink/app`,
owned by the watch service UID, mode 0700 (same-user clients) or 0750 (group
clients). Every ancestor must be owned by root or that UID, with no group/other
write permission; root-owned sticky ancestors are accepted. Symlink components
and special directory mode bits are rejected. Use `/run`, not a `/var/run`
symlink. Root and processes sharing the service UID are trusted filesystem
owners; the API does not isolate mutually hostile processes with the same UID.

For group clients, provision the directory's group and include that group in
the service's supplementary groups as well as the readers'. The server creates
`uplink.sock` with that group and mode 0660; it does not create directories or
change service-wide ownership, umask, mounts or capabilities. No extra persistent
CAP_CHOWN is required. A deployment repository can provision the directory using
systemd-tmpfiles or an equivalent install script before starting the service.

```sh
vpnctl node relay target reconcile --config /etc/vpnctl/node.yaml \
  --target-id app --watch \
  --uplink-api-dir /run/vpnctl-uplink/app \
  --uplink-api-allow-uids 1001,1002
```

Both API flags are required together, only with target reconcile `--watch`.
Allowed UIDs are explicit (1–16 unique canonical decimal values); root is not
implicitly allowed. Socket filesystem access and SO_PEERCRED UID authorization
must both succeed. No TCP listener or mutation/admin operation is exposed.
Leave both flags absent to retain the existing watch behavior.

`uplink.lock` is a persistent regular file, owned by the service UID, mode 0600,
with one hard link and an exclusive nonblocking flock. A second owner fails.
Under that lock, only an old socket with the expected UID/group/mode is removed.
Other files/symlinks are preserved and startup fails. Directory descriptors pin
the filesystem operations. Shutdown removes only the socket inode this process
created, preserving any replacement. The lock file stays for the next owner.

Consumers must independently validate the directory/socket ownership and mode,
then the server's SO_PEERCRED UID. `internal/uplinkapi.Dial` implements this for
Go. Unix pathname access or an HTTP 200 alone does not authenticate a producer.
Consumers also check the same boot/network clock domain, zero time-namespace
offsets, and absolute BOOTTIME deadline at receipt and before use.

## HTTP/1.1 and events

One GET request per connection; connections close after the response. Bodies,
transfer encoding, absolute-form URLs, unexpected queries, mutation verbs and
HTTP pipelining/keepalive are unsupported. `GET /v1/status` returns:

```json
{"schema_version":1,"type":"snapshot","cursor":"<32 lower-hex digits>:<decimal sequence>","snapshot":{"schema_version":1,"target_id":"app","producer_id":"...","revision":"2","availability":"unknown","freshness":"unknown","reason":"observation_unavailable","clock_domain":"v1:...","remaining_validity_ms":0,"path_revision":"0","session_continuity":"not_established"}}
```

`GET /v1/events?after=<cursor>` streams newline-delimited JSON frames with the
same shape. The query is optional. Every connection begins with a full snapshot.
Malformed cursors return 400. Old/unavailable cursors, a changed producer or
skipped publications emit `type: reset` **with a full snapshot**. There is no
history replay: clients tolerate duplicates and resynchronize from reset frames.
The cursor includes a random transport incarnation, independent of the producer
ID/revision; restarting the listener invalidates old cursors.

Streams sample at most every 250ms. Expiry becomes an event even when no new
reconcile completes. A full heartbeat snapshot is sent after five quiet seconds;
this never renews evidence. Streams end after 30 seconds or 64KiB; reconnect with
bounded backoff/jitter. Slow writes terminate within 200ms. A client must still
check the absolute deadline: a frame can expire while waiting in a socket.

`GET /v1/health` returns API running/connection/stream counts and cumulative
accepted, denied, limited and malformed counters. These contain no route/cache
metadata. API availability and data-path availability are independent. Access
control and rate limits also apply to health queries. Invalid requests use
bounded `{"error":"invalid_request"}` responses; overload uses 429 or closes
the connection before any state is exposed.

## Fixed resource bounds

| Resource | Limit |
| --- | --- |
| Accepted connection attempts | 40/s, paced before accept, including unauthorized peers |
| Request admission | 16/s global, burst 16; 8/s per UID, burst 8 |
| Active handlers/connections | 16 globally |
| Event streams | 4 globally, 2 per UID |
| Request bytes / record bytes | 4096 / 4096 |
| Retention / subscriber queue | Latest record identity only / no queue |
| Stream output / lifetime | 64KiB / 30s |
| Header read / write deadline | 2s / 200ms |

The fixed UID table never grows from client-provided values. Authentication and
admission happen before spawning a handler. Excess connections may wait in the
kernel's finite listen backlog; callers must bound connect/read time themselves.
An abusive allowed UID can deny other API clients availability. These limits
bound server work, not promise per-client fairness or hard realtime scheduling.
Readers never acquire relay cache/kernel ownership, start probes, or call the
controller. API locks are separate from the route producer.

## Qualification

The local race/load regression uses a separate client process, five seconds of
baseline followed by five seconds of mixed requests, short non-reading streams and partial
headers. Before running, limits were fixed at server CPU ≤1 second during load,
FD/goroutine increases ≤48 each and RSS increase ≤64MiB. It checks continued
sample publication and cleanup. This is a transport test, not a route SLO proof.

The existing disposable VM capacity matrix supports `--uplink-api-load` for
the same 4/8 candidate and CPU profiles. Both watches expose their own API;
clients run in the measurement/server role. The original lease, payload and
continuous freshness gates remain unchanged, and the load profile additionally
requires valid fresh reachable responses and overload rejections for both apps.
Worker readiness and monotonic start/stop evidence must cover the qualification
window; a worker watchdog expiry cannot pass as completed load.
Compare API-off and API-on trials with identical commit/image/build/CPU settings.
An incomplete or failed baseline/load trial cannot qualify the comparison.
This runner keeps all network/power effects inside its owned guests.
