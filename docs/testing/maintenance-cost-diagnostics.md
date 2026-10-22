# Maintenance cost diagnostic

This experimental branch adds duration-only boundaries to the existing cost
recorder. It does not change authority, ownership, journal writes, commands,
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

The follow-up diagnostic records process-self user/system CPU deltas at the
`maintenance` and `lease_staged` boundaries only. `sampled_calls` and
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
