# Targeted passive TCP diagnosis (never merge this experiment branch)

This branch replaces `reliability.yml` only for a manually dispatched diagnostic
experiment. It does not replace, waive or qualify the main/PR checks. The fixed
product and test source is `14ccf89cafd941b8d6fd2727bdbd69f8addc1c67`: main
`d47a1e0` plus the two history-query changes from PR #266. The public PR head is
not changed by this experiment. Source checkout, race build, revision, clean
status and input hashes are checked and retained.

One dispatch runs four fresh VMs sequentially, all with tracing enabled. Each
runs the original eight-candidate, two-application capacity test with healthy
indices 0, 3 and 7. Robot and server/measurement each retain one guest CPU;
the outer container has two CPUs, 2 GiB RAM, no swap, no network, no capabilities,
and only `/dev/kvm`. All existing 1-second connect, 15-second steady workload,
cycle-count and 10-second publication checks remain unchanged. All four
predeclared original exits are retained, even after a failure. No reruns,
adaptive retries, timeout increases or success-only selection.

Purpose: distinguish failure to establish TCP in the kernel from a kernel
establishment that Go observes late, or a later payload failure, in the hosted
CI environment of failed run 39699878690. This combined source includes the
subsequent expiry-checkpoint fix; it is not byte-identical to that historical
failure. A failure absent from these four VMs remains unresolved. A scheduling
cause cannot be inferred merely from a timestamp gap.

The collector runs only in an identity-guarded x86_64 two-CPU guest. It observes
connect, getsockopt, getpeername and TCP state tracepoints on both CPUs using
native perf rings. No ptrace, BPF, payload capture or user-memory dereference.
It records at most 30,000 events per fixture, 64 pages per ring, for at most
180 seconds. Each payload's existing worker PID is retained after its original
measurement. Attribution follows PID/FD generation and socket identity across
foreign kernel threads; it never guesses a connection from temporal proximity.
Unavailable/pre-SYN attribution stays explicit. A getsockopt syscall return of
zero does not establish that the socket's SO_ERROR value was zero.

Raw events, counters, per-CPU coverage and metadata must agree exactly, including
integer nanoseconds. Event loss, throttling, missing artifacts, unattributed
payloads or export failure make the diagnostic outcome fail. The original
observer exit is separately retained and cannot be replaced by export success.
Guest sync is performed only after the original worker exits. Offline export
repairs a disk copy if necessary and verifies that the original is unchanged.

Memory uses `/proc/self/status` VmRSS/VmHWM before capture and after capture,
before export. These cover only the collector address space, not kernel rings,
parent report parsing or JSON export overhead. The old rusage peak is explicitly
labelled as potentially including process launch memory. It is not an
incremental total instrumentation memory measurement.

Only a disposable GitHub-hosted runner on attempt 1 may invoke the controller.
KVM ACL setup is restricted to that disposable runner. This controller must not
be invoked on a shared workstation or lab host. Raw output is private locally;
only the bounded GPG-encrypted evidence archive is uploaded, for 14 days, using
the existing off-runner recipient key. No raw logs or VM disks are published.

Before dispatch: Python controller/collector/export regressions, Go metadata
regression with the actual overlay, clean product build, and source/context
hash checks must pass. The private lab validates the same collector, exact
overlay and guest lifecycle with one owned VM; it is not a hosted-runner result.
