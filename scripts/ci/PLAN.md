# Race versus ordinary Go build comparison

Experiment-only branch; never merge this workflow into main. This is diagnostic
comparison evidence, not a change to existing PR gates or deployment SLOs.
Fixed source: `7af8b777a13a0acef5c685c6cbf817201a945b9e`. No product, app, server,
lease, freshness, retry, or timeout changes. Prior run 38906246208 remains final:
eight unforced diagnostic passes and the preserved injected-stall failure.

Question: does Go race instrumentation materially affect the existing eight-path
observation and app behavior under the same role budget? This changes the build
mode of vpnctl, integration.test, and uplink-go together. It does not isolate the
Go client, identify GC as a cause, or compare Go with Rust/Python performance.

## Fixed schedule

Every invocation has a fresh disposable guest overlay and fixture. Two ordered
repetitions per capacity/API diagnostic cell, second block reversed. Finish with
one original full 15-phase app trial per mode; do not estimate reliability from
one full trial or two diagnostic repetitions. No process-stall injection here.

| Order | Case | Go race instrumentation |
| --- | --- | --- |
| 1 | application-capacity-8 | on |
| 2 | application-capacity-8 | off |
| 3 | uplink-diag-api | off |
| 4 | uplink-diag-api | on |
| 5 | uplink-diag-api | on |
| 6 | uplink-diag-api | off |
| 7 | application-capacity-8 | off |
| 8 | application-capacity-8 | on |
| 9 | uplink-apps-8 | on |
| 10 | uplink-apps-8 | off |

All: split two outer/guest CPUs; robot supervisor, two selectors and apps share
0.5 CPU on CPU0; controller/relays/measurement use one CPU on CPU1. Container
2GiB/no swap/no network/no capabilities, guest768MiB. Capacity API load is OFF;
the separate API diagnostic renames app sockets and observes the fixed45s window.
The original one-second app connect/I/O and two-second server read limits stay.

## Build and evidence controls

Build each mode once, on the first invocation of that mode. Ordinary build uses
the exact container image ID from the race preparation, not a tag or a second
apt/kernel build. Verify matching kernel/initrd hashes and all Python modules.
All three active Go executables must differ in hash, report the expected -race
setting via `go version -m`, and have the same Go version and other build settings.
Preserve all11 binaries/modules per image; historical migration binaries are not
executed by these cases and their temporary source paths can change their hashes.
Disk files necessarily differ, so verify each disk against its own immutable
manifest rather than claiming the two disks are byte-identical.

Reuse each prepared guest base without rebuilding; retain hashes before/after
and compare each trial's runner manifest. A failed first preparation is never
retried. A failed trial still permits later scheduled trials on its valid image.
Build overhead precedes the first two trials; order/environment effects cannot
be completely excluded. No selective retries and no cancellation to seek green.

Keep worker exits, original reports and assertions, app histories, resource
counters, candidate ownership/probe spans and publication verdicts. Diagnostic
success must stay qualified=false; normal capacity/full-app success must meet
the original qualified=true contract. Any failure keeps the workflow nonzero.
Ordinary-build success cannot waive an existing race safety/capacity CI failure.

Raw evidence/binaries stay encrypted with the off-runner private key. Watchdogs:
35m for each initial build/trial,25m for later trials,285m execution and310m job;
these are experiment bounds, not app recovery targets. Never alter local host
network, kernel, clock, power, or suspend processes on the local host.

## Interpretation and next step

Compare each original failure class, frozen observation/publication boundaries,
and app transaction histories first; report failed/incomplete windows as such.
Detailed server/selector logs are collected by the API diagnostic; the original
full app trial preserves worker assertions and transaction histories but does not
collect the same server-close logs. Do not infer its server closure reason from
a nearby diagnostic run. Any additional profiling belongs to a separate source.
CPU/time/RSS metrics describe this constrained fixture, not a hardware capacity
claim. Both passing is non-reproduction, not proof of equivalence. Ordinary-only
success supports instrumentation sensitivity, not a language defect or a fix.
Both failing means instrumentation alone is insufficient as an explanation.

After this comparison, select the reproducible delayed path for separate bounded
GC/scheduler, lock, and external-command diagnostics with instrumentation controls.
Do not inject new profiling overhead into this first comparison. Consider a
small Rust implementation only if measured runtime cost justifies the comparison;
no rewrite or new dependency is authorized by a lack of causal evidence.
