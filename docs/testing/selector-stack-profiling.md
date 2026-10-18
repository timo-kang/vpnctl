# Diagnostic selector CPU and allocation stacks

This experiment follows #251. It is not a production optimization or a merge
qualification. The source extends the immutable runtime-counter experiment
`b58417a5da98c103cacce88af060c80b6c1142ff`. All application, lease, freshness, ownership and failure gates
remain in force.

## Collection boundary

`VPNCTL_VM_PROFILE=1` compiles **only the CLI** with `vpnctl_profile`. The runner
must verify the tag in actual Go executable build metadata. Ordinary production
builds have no hook or profiling package. The diagnostic tag is present in both
control and instrumented images; `--selector-profile` is the independent runtime
intervention. Only the steady eight-path, split CPU, robot 0.5 CPU, API-off case
accepts that switch. Guest requests are strict booleans and reset inherited mode
and producer paths. Only the app2 selector receives a private output path.

Build from an independent clean checkout with a real `.git` directory. Local
review reproduced Go 1.25 stamping an enclosing repository's commit for a nested
linked worktree. The experiment runner rejects a tagged CLI unless its actual
embedded `vcs.revision` equals the fixed source and `vcs.modified` is false.

The original draft proposed eight seconds from process startup. Review found
that this could mostly observe startup before the two selectors contend. Before
any remote run, the protocol was amended: arm the collector at startup, then
trigger **once after the original two publication baselines are captured**.
The fixture records its trigger clock bracket and expected producer PID.
The selector polls for that private zero-byte trigger at 100 ms intervals, with
a two-minute wait ceiling. No signal, route, deadline, or qualification outcome
is changed. Missing instrumentation or an early process exit is unavailable
evidence; the fixture never waits for the profiler to finish.

The collector writes a cumulative sampled allocation profile, starts the default
Go CPU profiler, waits eight seconds, stops and drains it, then writes a second
cumulative allocation profile. Actual start/stop and allocation-read brackets
use `CLOCK_MONOTONIC` in the guest. Scheduling can extend the requested window.
The interval may include partial cycles and failure cleanup; compare it with
the original frozen window before attributing any samples to that window.
Never use a later profile or publication to repair the original verdict.

## Bounds and interpretation

- Fresh exclusive 0700 directory; exclusive 0600 files; no overwrite or HTTP
  profiling endpoint. Ready and final metadata include PID, role, source/runtime
  identity, sample rate, clocks and per-file sizes/SHA-256/status.
- Three profiles are capped at 256 KiB each. A cap or I/O error produces explicit
  unavailable/truncated evidence. The writer continues draining the runtime.
  Missing final metadata is incomplete, even if a partial profile parses.
- A conflicting CPU profiler is reported without stopping its owner. Collector
  errors never exit, kill, stop or prolong the selector process.
- Transport accepts only the five fixed names, pins each directory with
  `O_NOFOLLOW`, rejects nonregular/oversized files and limits profile collection
  to three fixtures. Binary bytes remain base64 inside the private result and
  are uploaded only in the existing encrypted experiment artifact.
- CPU stacks sample **this Go process**, not its nft/ip/wg children or time
  queued without CPU. Child CPU and ownership timing remain separate evidence.
  C/race-detector/syscall work may be unattributed. At least 50 CPU samples are
  required to rank hot paths; fewer samples are insufficient, not zero cost.
- Allocation profiles use the unchanged default sample rate. No forced GC,
  `GOGC`/`GOMAXPROCS` adjustment, memory cap change or new kernel requirement.
  Cumulative allocation samples may lag two GC cycles; a before/after difference
  is not an exact interval allocation total or RSS. Profiler allocations also
  contribute. See the version-matched [Go pprof documentation](https://pkg.go.dev/runtime/pprof@go1.25.0)
  and [MemProfile contract](https://pkg.go.dev/runtime@go1.25.0#MemProfile).

## Fixed remote design

Eight invocations once each: race/profile OFF, ordinary/OFF, ordinary/ON,
race/ON, then reverse. Child cost details and runtime counters are ON in every
cell. Same source, Docker base, kernel/initrd, CPU model and per-build immutable
image; two selectors, eight paths, robot 0.5 CPU on guest CPU 0, server and
measurement 1 CPU on guest CPU 1. Existing container and guest memory, network,
capability and host-isolation boundaries stay unchanged.

Acceptance requires original verdict replay, source/build/role/hash checks,
all eight outcomes (including failures), collection completeness and actual
clock coverage, and an OFF/ON comparison of the existing cycle metrics. Raw
profiles and unadopted measurements remain private. Two repetitions are
descriptive; this does not justify a language rewrite, relaxed gate, universal
capacity claim, or merging a previously failing PR. Do not retry an unchanged
source to find green or extend a sample after seeing insufficient data.
