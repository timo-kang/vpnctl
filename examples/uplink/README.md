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

This slice establishes observation consumption. Authenticated application echo,
payload reconnect metrics and the two-app VM fault matrix are subsequent #228
increments. This does not close #228 or qualify a target hardware recovery SLO.
