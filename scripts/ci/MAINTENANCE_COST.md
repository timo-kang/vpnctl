# Fixed maintenance duration cohort

Diagnostic-only workflow; never merge its replacement of reliability CI.

Compare clean main 092c1d1 with its duration-only diagnostic descendant. Build
both CLIs once, Go 1.25.0 with race, and use the unchanged main integration suite,
Python observer, guest agent, validators and script. Check actual CLI build
metadata and hashes. Freeze one runtime image for all cells, retain manifests
and compare all non-CLI guest inputs after completion. No packet recorder,
profiler, integration overlay, new retry or altered freshness gate is present.

Run baseline, diagnostic, diagnostic, baseline on one fresh disposable
ubuntu-24.04 GitHub runner. Each cell creates a new isolated VM using the original
script. Use 8 candidates, healthy positions 0/3/7, two apps, robot CPU0=1 CPU,
server CPU1=1 CPU, outer 2 CPU/2 GiB/no swap, guest 768 MiB. Original minimum 15s
steady/three further applied cycles, 10s freshness, 1s TCP and lease gates remain.
Preserve all natural failures and incomplete preparation. Never retry a cell.
Restore KVM access only on the disposable runner before a cell, as already tested.

Analyze original verdicts before durations. Compare complete cycles in the frozen
qualification interval separately from startup and failure cleanup. Require new
phase presence only for work actually reached. Keep aggregate command counts at
their original parent; durations are nested, not additive. In particular guard
inventory spans both maintenance and candidate/application checks.

The omitted time is not known to be CPU, BPF load, fsync or network latency.
The new measurements are attribution evidence, not an optimization, proof that
the original publication failure reproduced, or resolution of the separate TCP
timeout in PR266. Review measurement effects against both controls. No public raw
data: use the existing bounded encrypted artifact and off-runner private key.
