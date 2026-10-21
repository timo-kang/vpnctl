# Two-app recovery VM trial (#228)

This trial runs the Go and Python reference applications as separate processes
inside the robot network namespace. A controller, two relays and the TLS server
run outside that namespace. No host power, clock, Wi-Fi or network fault is used.
The existing QEMU runner remains inside a network-none container with all
capabilities removed. Each invocation owns its image, namespaces and result dir.

Run profiles serially with new, empty result directories:

```sh
VPNCTL_VM_CPUS=2 VPNCTL_ARTIFACT_DIR=/tmp/uplink-apps-4 \
  scripts/test-vm.sh --case uplink-apps-4 --robot-cpus 1 --cpu-layout split
VPNCTL_VM_CPUS=2 VPNCTL_ARTIFACT_DIR=/tmp/uplink-apps-8 \
  scripts/test-vm.sh --case uplink-apps-8 --robot-cpus 1 --cpu-layout split
```

The CI split profile reserves guest CPU 0 with a 1 CPU quota for the supervisor,
two selectors and two reference apps. CPU 1 has a 1 CPU quota for the controller,
relays, TLS server and measurement worker. Membership and before/after CPU
accounting are checked. These are reproducible sandbox profiles, not hardware
qualification for Jetson, Raspberry Pi, NUC, Qualcomm or other deployment CPUs.
Manual stress runs may explicitly select `--robot-cpus 0.5` or `0.25`; the
requested quota is passed to the guest and checked against before/after evidence.
Historical 0.5 CPU results retain their original profile and verdict.

The VM manifest verifies the Go binary and each Python module used in the guest.
A cached image must contain the matching new harness and packaging scripts.
The trial extends only the fixture-owned forwarding/SNAT chain to permit its TLS
service on 9193. Product ACL and approval guards retain their existing behavior.
After each blocked window a separate authenticated TLS probe inside the server
namespace must succeed on loopback. A stopped server or its own global timeout
cannot qualify an approval/fallback block.
Selector probes use 9192; a successful TCP probe does not prove TLS service health.

## Fixed sequence and bounds

Each 4/8-path trial executes this sequence once, without automatic retry:

1. Prove both target TLS services work through an actual default fallback before
   re-reserving their routes, then establish both apps on path p00.
2. Make the API socket names unavailable while selectors continue running.
   Existing streams drain naturally. After both apps observe API outage, require
   additional correct payload on their existing authenticated sockets.
3. Restart both producers and require each consumer to observe a different
   producer identity and post-event payload.
4. Block only app's TLS service, leaving app2 and the TCP probes available; recover.
5. Blackhole the preferred underlay and require p01 on the same relay.
6. Disable that relay's uplink and require p11 on the other relay.
7. Disable both uplinks, observe repeated failed reconnects, then restore them.
8. Install a 60-second node approval, prove its generation was applied, isolate
   its controller connection, verify valid offline operation, then expiry.
   Relays receive an independent longer approval and must remain live.
9. Restore authority and recover; revoke the node certificate, allow the existing
   bounded refresh contract to observe denial, then verify repeated reconnects
   remain blocked even after another controller outage.

An app runs at most 580 seconds with the documented one-second connect and I/O
deadlines and 250 ms healthy interval. Payload retry uses independent jittered
backoff capped at eight seconds. The read-only echo server allows 600 seconds and
12000 requests per session, so its per-session cap exceeds the app duration.
The server's separate global 600-second timer starts earlier; the independent
post-window service checks must still succeed. Two-second server I/O timeouts
apply throughout.

Each phase has a 75-second observation watchdog. A blocked phase requires a
20-second window, multiple failed operations, and an actual new socket attempt.
These limits bound the experiment and its resource use. **Measure first; app
recovery SLO values are specified at deployment.** An incomplete observation
window does not establish a performance threshold or a successful recovery.

## Evidence and limitations

`uplink-applications.json` retains per-app final transaction histories, bounded
progress snapshots, phase boundaries, sampled route results, and resource costs.
`observer.jsonl` contains the validated per-app measurements. Reports and failed
private VM disks are retained; do not publish unreviewed logs or private disks.

On a test failure, each started app gets SIGTERM and up to 12 seconds to emit its
final bounded request history before forced termination. `client_cleanup`
records `drained`, `failed`, `forced`, or `already_stopped` per started app.
Cleanup-time events are diagnostic only: the original failed verdict and
unfinished phase remain unchanged. An unresponsive client may still lack final
events; its last progress is not a replacement for the complete history.
Terminal worker results also include a filtered 32 KiB log tail, or
`worker_log_error: unavailable` if that optional log cannot be read safely.
Missing or unsafe logs never replace the original worker exit or reports.

Every operation has a new request ID and nonce. Only an exact response over a
verified TLS connection counts as correct. The validator reconciles counters
against the complete history, rejects duplicate/out-of-order IDs and socket
reuse after failure, and rejects **any** correct operation started after a
blocking fault completed and finished within that observation window. Replies
to earlier in-flight operations and operations crossing the window's end are
excluded from its verdict. A healthy app's result never substitutes for its peer.

Measurements include fault-completion to first correct response, authenticated
connect when a new socket was required, existing/new socket classification,
completed response gaps, uncertain outcomes, CPU deltas and peak RSS. An uncertain
request is not a confirmed server-side loss. The read-only protocol is not a
business-operation idempotency or duplicate-side-effect guarantee.

Route observations are sampled upper bounds. Exact route-application, API
publication and API receipt timestamps are **missing and explicitly null**;
progress timestamps must not replace them. No-response windows and an unrecovered
tail are retained explicitly. A completed success-to-success gap excludes an
ongoing final outage. One sandbox execution is not a latency distribution or a
deployment SLO certification; repeat the fixed profile on deployment hardware
before assigning application-specific thresholds.

Host-safe verification: `python3 -B -m unittest discover -s tests/vm` exercises
missing/reordered evidence, stale progress, fake recovery, wrong route, blocked
new-nonce success and absent reconnects. The integration test skips on a normal
host and checks the provisioned guest identity before any namespace mutation.
