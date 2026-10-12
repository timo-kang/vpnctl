# Local uplink reference consumers (#228)

Linux reference implementations for the read-only API in
[`uplink-api.md`](../../docs/deployment/uplink-api.md). These observe one target
in the producer's network and time namespaces; they do not change routes, renew
approval, control robot movement, or establish payload/session continuity.
The Go package is internal to this repository, not a separately versioned SDK.
Python uses only the standard library.

## Consume observations

Create one state per target and one API watcher per state. Configure the expected
service UID independently of the endpoint. Do not infer trust from response
headers or disable directory/socket/peer checks when deploying to another UID.
Provision the private runtime directory and group access as described in the
deployment guide. Neither consumer creates or changes runtime permissions.

Go (inside this module):

```go
state, err := uplinkclient.NewState("app")
if err != nil { return err }
go uplinkclient.Watch(ctx, uplinkclient.Options{
    Directory: "/run/vpnctl/app", ServerUID: serviceUID,
}, state)
// Read again at every use: expiry can occur without another API event.
observation := state.Current()
```

Python (add `examples/uplink/python` to the import path):

```python
import threading
from vpnctl_uplink import State
from transport import watch

state, stop = State('app'), threading.Event()
worker = threading.Thread(target=watch, args=('/run/vpnctl/app', service_uid, state, stop))
worker.start()
observation = state.current()  # Recheck at every use.
stop.set()
worker.join()
```

An API outage sets `api_available` false while retaining the last observation
only until its original absolute deadline. Receiving a duplicate or reconnecting
does not renew that deadline. Invalid frames, clock failure, and observed expiry
withdraw confidence until a newer valid publication; producer replacement and
cursor gaps require resynchronization. Only the latest observation is retained.
Closing a stream retires its callbacks even before a replacement stream starts.

Keep application I/O independent. In particular, unknown/stale API status is
not an instruction to close a working application connection. Reachable status
only proves the producer's newly opened TCP probe, not authentication, a correct
application response, or continuity of an existing session. Never replay an
ambiguous business operation based on a path event.

## Bounds and compatibility

Both implementations enforce schema 1, canonical uint64 decimal-string counters,
producer/target identity, cursor and publication ordering, independently checked
BOOTTIME domain, and absolute expiry at receipt and use. Unknown additive fields
are allowed within frame/depth limits. Duplicate JSON keys, case aliases,
noncanonical counters, nonfinite values, and contradictory evidence are rejected.
Informational age and remaining milliseconds never authorize a fresh view.

Each stream authenticates the Unix peer UID after resolving every directory
component without symlinks. Connect and write have one-second deadlines; headers
have a two-second absolute deadline. NDJSON records have a six-second deadline
(the server heartbeat interval is five seconds). Headers and records are bounded
to 4096 bytes, a stream to 64 KiB of records and approximately 35 seconds.
Only complete newline-terminated records are installed; there is no delivery
queue. Cancellation interrupts reads and backoff.

API reconnect uses exponential backoff with equal jitter: 125–250 ms initially,
doubling to a 4–8 second interval. A validated API record resets **only API**
backoff. These limits are resource/watchdog bounds, not application recovery
SLOs. `AcceptedFrames` / `accepted_frames()` counts valid records, including
heartbeats; a count is not a fresh-observation or payload-success count.

## Verification and remaining scope

`go test ./internal/uplinkclient` runs the shared Go state vectors, Python unit
suite, and both languages against the actual Unix producer. Python can also run
independently with `python3 -B -m unittest discover -s examples/uplink/python`.
Tests cover malformed/truncated streams, byte budgets, cancellation, unsafe
runtime directories, clock/expiry latching, duplicate/order/reset behavior, and
late callbacks from retired connections.

## Read-only application echo

The Go CLI (`go run ./examples/uplink/go`) and Python CLI
(`python3 -B examples/uplink/python/main.py`) run an independent API watcher and
a persistent TLS 1.3 echo session. Provision a trusted CA and a server certificate
whose SAN matches `--server-name`. `--address` must use a literal IP and port;
server identity verification remains mandatory. No DNS timing or plaintext
fallback is hidden in the connection budget.

For a disposable test endpoint, run `python3 -B
examples/uplink/python/echo_server.py --host 127.0.0.1 --port 9443 --cert
server.pem --key server-key.pem`. This bounded server accepts only the read-only
echo protocol, up to eight simultaneous clients, with 256 requests/30 seconds
per session and two-second I/O limits. It is not a business-operation server.

Example clients (replace runtime, UID and certificate paths with deployment
values):

```sh
go run ./examples/uplink/go --address 127.0.0.1:9443 \
  --server-name uplink.example --ca ca.pem --runtime /run/vpnctl/app \
  --server-uid 1001 --target app --duration 60s --progress /tmp/app-progress.json

python3 -B examples/uplink/python/main.py --address 127.0.0.1:9443 \
  --server-name uplink.example --ca ca.pem --runtime /run/vpnctl/app2 \
  --server-uid 1001 --target app2 --duration 60 --progress /tmp/app2-progress.json
```

Go duration arguments include units; Python durations are seconds. Both accept
`--connect-timeout`, `--io-timeout`, and `--interval`. Defaults are one second for
TCP+TLS establishment, one second each for write/read, and 250 ms between healthy
echoes. Duration is bounded to 1–600 seconds. Payload retry uses the same bounded
equal-jitter exponential schedule as the API, with independent state. Only an
authenticated response exactly matching the request ID and random nonce resets
payload backoff. Every new attempt uses a new request ID and nonce; an incomplete
response is reported as **outcome unknown**, not replayed. Do not substitute
arbitrary business requests without the application's idempotency contract.

Healthy payload sessions continue during API outage, unknown/stale status and
producer replacement. These examples observe path events but do not accelerate
retry on them. Such hints may be added only within an application's retry budget;
they must never imply a required session replacement or confirmed recovery.

Both CLIs write a final JSON report to stdout. The optional progress file is
atomically replaced every 250 ms and omits the event history. Final reports keep
at most 4096 transaction events; `dropped_events` explicitly counts eviction.
Each event records the operation number, socket identity, authenticated connect
time when applicable, completion time, response validity, uncertain outcome and
next retry delay. Nanoseconds are decimal strings. Socket reuse is distinguished
from a new connection; reuse alone does not assert uninterrupted delivery.

`max_correct_gap_ns` measures only **completed success-to-success intervals**.
It excludes an ongoing outage at the end. `no_correct_response` identifies runs
with no successful payload, and `response_age_ns` reports time since the last
correct response (null when none exists). Keep these fields when assessing
unrecovered cases. A first response before a fault cannot qualify recovery after
that fault. CPU user/system deltas and process lifetime peak RSS are included;
resource claims require separate processes in a controlled environment.

Publication and exact API receipt boundaries are currently absent and explicitly
null. API record counts and periodic progress timestamps must not be substituted
for those boundaries. The next VM increment must add or mark missing route,
publication and receipt evidence and correlate each application's post-fault
payload separately.

Local tests exercise real Go/Python TLS clients, wrong server identity,
nonce-only mismatch, previous-response replay, independent retry backoff, and
payload continuation after API outage/producer replacement. They do not prove
multi-relay/underlay switching, approval quarantine or target hardware behavior.
The two-app VM fault matrix remains part of #228. Per the deployment decision,
measure recovery first; application SLO values are specified at deployment.
Watchdog durations and selector freshness are not application pass thresholds.
