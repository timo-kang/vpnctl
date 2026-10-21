# Capacity preparation failure evidence

The capacity fixture reserves its private `m3-authority-*` artifact directory
and registers the `application-mixed-candidates.json` writer before resource
setup or network preparation. A failed device-bound candidate convergence check
therefore leaves an identifiable failed case even when neither application
measurement window has started.

The fixture, kernel snapshots, supervisor logs and capacity report use that same
directory. Its report writer runs after all subsequently registered fixture and
resource cleanups, so a cleanup error cannot leave `completed: true` behind.

## Interpretation

- `requested_profile` identifies the requested path count, CPU quota, CPU layout
  and rebuild mode. It does not prove that those resources were established;
  existing resource and role-placement evidence still provides that proof.
- `phase` names the last entered stage: `resources`, `preparation`, `rebuild_setup`,
  `app2_activation`, `fault_setup`, `application_convergence`,
  `steady_qualification`, `final_verification`, or `completed`.
- `preparation_completed` becomes true only after candidate preparation and both
  target reservations return successfully.
- `test_outcome` records the final Go test state, including cleanup failures.
  A failed-and-skipped test is reported as `failed`.
- `completed` requires both the final successful stage and a passing test.
  Reaching `phase: completed` does not override a subsequent cleanup failure.
- Before steady qualification begins, publication continuity and sampled
  qualification are `not_started`. Missing latency, samples and publication
  windows remain unmeasured; they are never populated with zero or a passing
  placeholder.

The report identifies the stage, not the underlying network cause. Existing
worker output and available supervisor/kernel logs retain the failure details.
The VM collector preserves early reports and logs, while its existing exit,
case-count, payload, lease, freshness and steady-window requirements still reject
an incomplete case. No timeout or qualification threshold changes in this fix.

## Worker diagnostics

A completed mixed/preparation/approval/capacity worker includes at most 32 KiB
of its final log using the existing sensitive-keyword filtering. A cut first
line is discarded, and diagnostics do not change the worker exit or verdict.
Missing or rejected logs produce `worker_log_error: unavailable` while retaining
the reports. Running workers do not export a partial log.

Artifact reads pin the parent directory and open the file without following a
symlink. They reject non-regular files before reading, so a FIFO cannot block
result collection. File size and content come from the same descriptor, and
all opened descriptors close even when validation or reading fails. These
checks apply to the shared direct-artifact reader as well as the new worker tail.

## Verification and limits

Host-safe subprocess regressions inject preparation Fatal, Skip, cleanup Fatal,
successful completion and a failure after completion. They exercise the real Go
cleanup order without creating network namespaces or cgroups. VM runner tests
exercise result collection and rejection of unmeasured cases without starting a
VM. Worker-log regressions also cover a blocking FIFO, a symlink replacement
after the path check, and repeated directory rejection without descriptor
leaks. The reliability workflow runs these regressions and the existing real VM
capacity matrix.

This change does not recover missing measurements from older runs and does not
resolve the shared-ownership contention tracked by #185. Abrupt process loss,
power loss, failure to create the artifact directory, or failure to write the
report may still leave missing evidence; matrix completeness must continue to
reject it. The original failed comparisons remain unchanged.
