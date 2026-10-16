# App connection-loss hypothesis experiment

Experiment-only branch. Never merge this workflow or diagnostic harness into
main. This experiment cannot qualify the original 15-phase application trial.
Fixed product/harness source: `7af8b777a13a0acef5c685c6cbf817201a945b9e`. Product and both real
client implementations are unchanged from 9c0700f; the test-only echo server
adds optional bounded close diagnostics. All candidate/approval safety checks,
client one-second connect/I/O deadlines and server two-second read limit stay.

Earlier 38858704963 completed both original app profiles successfully at9c0700f;
all15 phases and original validators passed. This does not resolve the prior
2fd9b52 eight-path failure and did not exercise failed-client cleanup in a guest.
The new experiment changes interventions and evidence rather than retrying the
old test for a green result. Original PR CI and old artifacts remain untouched.

Hypotheses: API outage coupling; whole-robot CPU contention; server idle close;
transient route/approval enforcement; environmental/order effects. Loopback real
TLS testing reproduced server idle timeout without VPN/API. This proves a
possible mechanism, not the cause of the original unforced incident. Refer to
fixed-source docs/testing/app-outage-hypotheses.md for evidence/causality limits.

Predeclared order, fresh disposable VM overlay and fixture for every invocation:

| Order | API socket | Robot quota | Injection |
| --- | --- | --- | --- |
| 1 | unchanged | 0.5 CPU | none |
| 2 | renamed/offline | 0.5 CPU | none |
| 3 | renamed/offline | 1 CPU | none |
| 4 | unchanged | 1 CPU | none |
| 5 | unchanged | 1 CPU | none |
| 6 | renamed/offline | 1 CPU | none |
| 7 | renamed/offline | 0.5 CPU | none |
| 8 | unchanged | 0.5 CPU | none |
| 9 | unchanged | 0.5 CPU | Go app child SIGSTOP3s then SIGCONT |

Each cell observes45 seconds after action completion, after a healthy baseline.
Two prespecified repetitions per cell, reversed order; no selective repeats.
The positive control deliberately challenges connection preservation and is
expected to return worker exit1. Retain that failure unchanged: workflow failure
is expected if the positive control works, and must not be called a product
regression. Check assertion, both final histories, cleanup states and server
read-timeout evidence. Expected failure cannot excuse an unrelated setup fault.

Successful diagnostic trials must explicitly remain qualified=false with
unsupported_reason=diagnostic_only_no_qualification and completed=true. Exit0
without that contract is rejected. All nonzero exits remain nonzero, including
positive control; later planned cells still execute. Full15-phase/CPU capacity
qualification gates are unchanged and cannot be replaced by these short windows.

One GitHub-hosted disposable ubuntu24.04 runner builds race binaries and image
once. Preserve all11 executable/module hashes, verify base image before/after
and against every runner manifest; no rebuild after initial failure. Fresh writable
overlays; only remove owned runtime after named container termination confirmed.
Host boot identity fixed. Split two guest/outer CPUs throughout; robot roles on
CPU0, controller/relays/measurement onCPU1. Container2GiB/no swap/no network/no
capabilities, guest768MiB. Quota1 changes the entire robot role budget, not just
the app; evidence cannot identify an individual process from that intervention.

Keep first35-minute build watchdog and later25-minute trial watchdogs, 245-minute
execution/270-minute job bounds with time to seal incomplete evidence. These are
experiment limits, never deployment SLOs. All raw logs/reports/binaries encrypted
before upload to an off-runner private key. No local host networking, kernel,
clock, power or process suspension. Only the owned guest app child is paused.
