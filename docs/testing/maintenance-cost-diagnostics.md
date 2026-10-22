# Maintenance cost diagnostic

This experimental branch adds nested duration boundaries and selected process
CPU counters to the existing cost recorder. It does not change authority, ownership, journal writes, commands,
timeouts, rearm windows, the nft conditional continuation or BPF proposals.
It is a diagnostic, not an adopted optimization or a merge qualification.

The retained publication failure shows an admitted maintenance sweep taking
longer than its summed external commands. External-command timing omits BPF
syscalls, Go work and file operations. This does not identify which omitted work
caused the delay, or explain the separate TCP connect timeout.

| Timer | Scope |
| --- | --- |
| `maintenance_approval_plan` | Current cache status, lease witness and underlay plan |
| `maintenance_consent` | Durable preparation consent read |
| `maintenance_kernel` | Candidate kernel ownership check |
| `maintenance_journal` | Changed approval journal persistence, when needed |
| `maintenance_authority` | Immediate current-approval check before renewal |
| `maintenance_renewal` | Lease operation, including initial short-grant continuation |
| `lease_staged` | Existing nft/BPF staged grant transaction |
| `lease_guard_inventory` | Live link, pins, program, map and attachment validation |
| `lease_guard_update` | Entire existing BPF compare-and-update operation |
| `lease_guard_load` | Build and load the transient BPF update program |
| `lease_guard_test` | Existing compare-and-update test-run syscall |

Child timers keep the caller's context, so external commands retain their
original phase attribution. These timers overlap: renewal contains staged,
staged contains guard update, and guard update contains inventory/load/test.
Inventory also occurs outside maintenance. Do not sum all durations or subtract
the whole-cycle inventory total from maintenance. Counts include failed calls;
an absent timer means that stage was not reached. No argv, payload, approval
material, path identifiers, per-path labels or unbounded checkpoint series is
added. In a context without a recorder, the timing hooks are no-ops.

Before interpreting the measurements, run a fixed baseline/diagnostic/diagnostic/
baseline cohort with identical original integration tests and resource gates.
Keep every natural failure and incomplete run. Timing differences alone do not
establish a fix. Raw and unadopted measurements remain private/encrypted.

## Process CPU attribution follow-up

The diagnostic records process-self user/system CPU deltas at `maintenance`,
`lease_staged`, `cache_state_encode` and `cache_state_persist`. `sampled_calls` and
`unavailable_calls` describe coverage; failed, regressed or overflowing reads
never count as successful zero-cost samples. Snapshot values are independent
copies. No command arguments, output, keys or dynamic identifiers are recorded.

The reads happen inside each existing duration interval. CPU includes all
threads of this process and excludes child commands. It is not per-goroutine
accounting, scheduler wait, or an exact wall-time partition. A background thread
can contribute, and CPU can exceed wall time. Staged and whole-maintenance
intervals overlap: do not add their CPU or durations. This diagnostic cannot
identify CPU versus I/O/scheduler causes without a reproduced slow interval and
controlled comparison; passing runs alone do not resolve the retained failure.

The baseline includes the independently reviewed historical-fixture `-trimpath`
fix, so future comparisons must build both modes with that same runner. Prior
cohort inputs and conclusions stay unchanged. This remains an experiment branch,
not an adopted performance change or a reason to waive a failed product gate.

## Clock checkpoint follow-up (diagnostic only)

The maintenance CPU cohort localized its slowest complete-window samples to
`maintenance_authority`. This follows `stillApproved` through `Store.Status`,
which durably advances the clock high-water mark. `StatusObserved` instruments
that exact path, including the initial maintenance status read. It records
`cache_status`, `cache_clock_checkpoint`, `cache_state_open`, `cache_state_encode`,
`cache_state_persist` and `cache_status_report`. The encode/persist phases also
sample process-self CPU. All are nested accounting, never authority evidence.

`cache_state_persist` encloses the existing `writeState` call, including its safe
file checks, replacement and file/directory sync. It is not a measured disk-wait
or individual-fsync duration. Clock values, raw JSON, paths and errors are not
added to diagnostics. No write or validation is skipped, including on a cancelled
accounting context, and pre-/post-rename error semantics remain identical.
Only maintenance opts into the nested records; other Status/approval callers
retain their existing calls and semantics. Failed writes still have timed
records, but incomplete work must not be called successful persistence.

## Storage-stage attribution (diagnostic only)

This follow-up is based on main d47a1e0 and retains the expiry checkpoint fix.
The six fixed stages `cache_file_prepare`, `cache_file_write`, `cache_file_sync`,
`cache_file_close`, `cache_file_rename`, `cache_directory_sync` surround the exact
existing operations. Preparation includes safe entry checks, temporary creation
and chmod. The directory phase includes opening and syncing the pinned directory.
An attempted stage is recorded even on error; later stages may be absent.
Neither call counts nor positive durations independently prove successful writes.
The expiry checkpoint inside reporting may add a second encode/persist sequence
per Status; it is accounted using the same mutex-owned temporary context.

The same RUSAGE_SELF reads also retain voluntary/involuntary context switches and
input/output block operation counts. All counters cover process threads, exclude
children and are nested with parent phases. They are event counts, not elapsed
scheduler wait, physical device latency or a way to subtract wall time into CPU
and I/O. Missing, regressed and overflowing samples retain explicit coverage gaps.
There is no thread pinning, scheduler tuning, skipped write, retry or timeout change.

A paired diagnostic runner must record the actual robot cache directory and state
file mount/device identity before app activation in BOTH modes. Outer-container
/tmp settings and a guest root mount alone are not proof of the cache filesystem.
The additive fixture hook must leave original assertions and window timing intact,
with identical test binaries in all four cells. Original verdicts precede any
interpretation. Raw results remain private; this branch has no product PR.
