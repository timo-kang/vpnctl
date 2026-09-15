# Probe lifecycle reliability

Scope: M1 issue #37, based on merged main `7e20899`. This report concerns
UDP/STUN probe execution and cancellation. It does not close the overall M1
gate (#13); process/controller shutdown (#38) and CI latency (#39) remain open.

## Reproduced defects

Before the fix, a shared STUN request with a 20ms budget did not return within
one second. `Client.Close` waited for its reader while `WithNoConnClose` left
that reader blocked on a pipe that was closed only afterward. Because the agent
runs STUN inside its event loop, the deadlock also stopped heartbeat and tunnel
health/recovery work.

A separate test completed 128 peer probes and 128 performance probes against a
local responder using `context.Background()`. Goroutines increased from 7 to
263: each call left a goroutine waiting for an owner context that never ended.

Further review and tests found:

- Closing the shared socket did not wake pending probe requests or DNS lookups.
- Synchronous STUN pipe writes could block the shared UDP reader and direct acks.
- Shared peer acks did not verify the sending endpoint.
- Cancelling an in-flight health check could be counted as tunnel failure.
- Socket deadlines could fire before `ctx.Err()` changed, misclassifying a
  parent deadline as measurement loss. New tests failed before this was fixed.
- After a slow STUN sweep, a pending ticker event could immediately start another
  sweep and delay heartbeat again. An actual agent-loop test exposed this after
  the initial probe-only tests had passed.

## Changes and contracts

STUN uses a bounded datagram adapter for the existing Pion client. Its original
transaction/retransmission mechanism is retained. Valid replies must match the
configured endpoint, transaction ID and binding response type. The one-packet
queue drops excess responses without blocking the shared reader. Closing the
STUN adapter releases the library reader without closing the shared socket.

Peer probes bind their nonce to the expected remote address. DNS resolution,
UDP writes and response waits share the request budget. Shared writes serialize
socket deadline changes and join cancellation callbacks before another writer
can change the deadline. Socket close cancels pending work and joins the reader.
Normal completion unregisters cancellation callbacks instead of retaining a
per-call goroutine. A nonpositive timeout retains the parent context semantics;
an explicitly unbounded parent still requires caller cancellation or socket close.

A performance probe's own measurement timeout may return partial loss statistics.
Parent cancellation/deadline and non-timeout I/O errors return errors. This change
does not redefine throughput statistics or duplicate-packet accounting; those
quality semantics require separate work in M2.

Health checks distinguish their own remote-reachability timeout from cancellation
of their owner, including the socket/context deadline race. Slow STUN sweeps
schedule the next sweep from completion, giving pending heartbeat/health work a
chance to run. A sweep still executes servers sequentially with a 5s per-server
budget; this is not a latency guarantee independent of the configured server list.

## Verification

Reproducible commands (all local socket tests use loopback):

```sh
go test -race ./internal/direct -count=20 -timeout=120s
go test -race ./internal/agent -run TestRunContinuesAfterSTUN -count=5 -timeout=90s
go test -race ./...
go vet ./...
go vet -tags=integration ./tests/integration
go build ./cmd/vpnctl
./scripts/test-netns.sh
```

The probe suite covers successful round trips, dropped first STUN request and
retransmission, silence, cancellation, parent deadline, missing mapped address,
error response, socket close during response wait/DNS, and reuse after failure.
It mixes 1/3/8/32/64 outstanding peer requests with cancellation and close, runs
64 peers concurrently with STUN, checks bounded pending state, and repeats
completed probes/STUN timeouts to detect resource accumulation.

Adversarial checks send wrong-source acks, wrong-source STUN replies, wrong
transaction IDs, malformed lengths and a 1,000-packet valid-response burst to a
STUN consumer that does not read. Direct response processing must continue.
The actual agent-loop test verifies repeated NAT reporting after STUN success,
heartbeat after a silent server's timeout, and prompt owner cancellation.

The final direct suite passed 20 repetitions and the actual agent-loop test
passed five repetitions. Full `go test -race ./...`, both vet commands and build
also passed. The kernel workflow covers 1/3/8/32 nodes, certificate transitions,
controller/node restart and injected packet loss; run-specific counts are
recorded on the associated PR and in the retained measurement artifacts.

## CI failure retained for follow-up

The merged-main [run 34946555633](https://github.com/timo-kang/vpnctl/actions/runs/34946555633)
passed Go race/vet/build but failed kernel checks. At 32 nodes there were 287
HTTPS deadline failures among 107,372 planned samples, with no application UDP/TCP
failure in those phases. At one node there was one UDP write timeout. Three- and
eight-node cases passed. These failed executions are not counted as successful
verification.

The UDP measurement worker used its 20ms send interval as a write deadline while
its documented request budget was 500ms. This follow-up aligns writes with the
same 500ms total budget; the 20ms sampling interval and 500ms response criterion
remain unchanged. Injected loss must still be detected.

A local production-build 2-CPU/32-node follow-up passed 95,747 planned samples
before that measurement correction. That does not establish the cause of the
CI HTTPS latency. Issue #39 tracks profiling and repeatability with the original
1s HTTPS criterion. Neither a single successful rerun nor this probe fix closes
that issue, and M1 remains incomplete.
