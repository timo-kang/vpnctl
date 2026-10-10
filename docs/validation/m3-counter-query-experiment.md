# Live WireGuard counter query experiment (#185, 2026-10-10)

## Verdict: not adopted

The single-query counter change reduced probe subprocess counts, but did not
qualify the required observation continuity in either candidate run. Whole-cycle
results were mixed across positions and repeats. The candidate remains an
unmerged experiment; main is `6100849c556739a1f8f8572eeff98f71d2c896f2`.
This is neither a fix for #185/#186 nor an M3/field SLO qualification.

Baseline: `6100849c556739a1f8f8572eeff98f71d2c896f2`.
Candidate: `2522969accfd86fbbe2baae9e7b9ce92bbc0ddbf`.
The rejected lease-maintenance overlap from PR #211 is not included.

## Change and security contract

At each existing TCP boundary, the candidate replaces separate WG handshake
and transfer queries with one fresh interface dump. Pre/post TCP reads remain
separate; evidence is not cached or reused across proofs. Live route, ownership,
authority and kernel lease checks are unchanged. The 3s wave and 10s freshness
and lease budgets are unchanged. This is a single live query, not an atomic
kernel snapshot guarantee. Field layout follows the official
[WireGuard manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

A dump contains private-key/PSK fields. The previous counter-only
`NeverReadSecrets` test contract was explicitly replaced with a bounded returned
raw-buffer erasure and no-secret-error contract. Existing ownership checks also
read dumps, but that does not make the increased counter-path secret exposure
free. The parser keeps key fields as byte slices, clears returned bytes on
success/error/cancellation, rejects extra peers/fields and malformed counters,
and returns generic parse errors. This does not claim erasure of all process
memory. Because acceptance failed, this tradeoff is not introduced into main.

## Method

Runs were preplanned as B1, C1, B2, C2 and executed sequentially without
cancellation, replacement of failures, or concurrent performance VMs. Each used
a new artifact directory. All four exited naturally with status 1. All three
healthy positions (0, 3, 7) were attempted in each run.

- Image: `sha256:9d03cc849d8a106345031c8a975bdae62dc0ac5bb7908d2ad5be3b75a10071f7`.
- Shared guest: 1 vCPU; entire VM quota 0.5 CPU; robot quota 0.5 CPU.
- Eight candidates, two automatic apps, seven first-app TCP blackholes; race build.
- Outer memory 2 GiB, guest 768 MiB, swap zero, network-none/capabilities-none runner.
- Identical diagnostic-only command-kind timing overlay on both source versions.
  Clean source manifests therefore still represent **instrumented** builds.
- Source/image/quota/host-boot/clock-drift and runner-isolation checks passed for
  all four artifacts. No host network/kernel/clock/power settings were changed.
- These whole-VM resource conditions are stricter than the usual 1-CPU shared
  CI case. They are not a minimum robot CPU specification or a field SLO.

Qualification still requires the existing minimum 15s/three-cycle steady
window, uninterrupted payload and leases, and fresh selected-path observations.
For timing comparisons, use post-fault applied `selected_path_verified` records
completed before the cleanup-entry failure-capture cutoff (not the exact
failing-check instant). This filters completion timestamps, not proven record
visibility to the observer. Early failures shorten the samples;
zero means no matching timing samples, not zero latency. Never infer pass rate
or a causal regression from these small counts.

`cycle` is the existing monotonic whole-cycle metric including admission.
`work` is FinishedAt minus StartedAt; `admission` is the existing admission phase.
`proof-to-completion` is FinishedAt minus selected ObservedAt. FinishedAt is not
stdout write completion or observer receipt, so this is **not exact publication
latency**. Phase/command sums may overlap and are not added to estimate elapsed.
All following times are arithmetic means in seconds, with per-role sample counts.

## Qualification results

| Run | Source | Position 0 | Position 3 | Position 7 | Qualified positions |
| --- | --- | --- | --- | --- | --- |
| B1 | baseline | PASS | FAIL | PASS | 2/3 |
| C1 | candidate | FAIL | FAIL | PASS | 1/3 |
| B2 | baseline | FAIL | FAIL | PASS | 1/3 |
| C2 | candidate | FAIL | FAIL | PASS | 1/3 |

All failed positions retain their failed qualification. Post-failure completion
or a later repeat cannot erase them. Both baseline and candidate failed under
this quota; these observations do not isolate a candidate-caused regression.
All seven failed positions reported the existing `latest selected-path
observation missing or stale` check. That combined error does not by itself
distinguish a missing/ineligible row from an exceeded age.

## Per-position timing evidence

### app

| Run | Healthy position | n | Cycle | Work | Admission | Proof-to-completion |
| --- | --- | --- | --- | --- | --- | --- |
| B1 | 0 | 3 | 6.720 | 3.243 | 3.477 | 2.057 |
| B1 | 3 | 0 | — | — | — | — |
| B1 | 7 | 3 | 7.077 | 3.372 | 3.705 | 1.559 |
| C1 | 0 | 1 | 7.600 | 3.205 | 4.396 | 1.938 |
| C1 | 3 | 0 | — | — | — | — |
| C1 | 7 | 3 | 6.527 | 3.022 | 3.505 | 1.277 |
| B2 | 0 | 0 | — | — | — | — |
| B2 | 3 | 0 | — | — | — | — |
| B2 | 7 | 3 | 7.100 | 3.362 | 3.738 | 1.437 |
| C2 | 0 | 0 | — | — | — | — |
| C2 | 3 | 0 | — | — | — | — |
| C2 | 7 | 3 | 6.843 | 3.125 | 3.718 | 1.418 |

### app2

| Run | Healthy position | n | Cycle | Work | Admission | Proof-to-completion |
| --- | --- | --- | --- | --- | --- | --- |
| B1 | 0 | 4 | 6.923 | 2.538 | 4.385 | 1.302 |
| B1 | 3 | 1 | 6.623 | 2.797 | 3.827 | 1.432 |
| B1 | 7 | 4 | 7.189 | 2.665 | 4.524 | 1.374 |
| C1 | 0 | 2 | 6.452 | 2.501 | 3.951 | 1.345 |
| C1 | 3 | 2 | 9.062 | 4.169 | 4.892 | 2.379 |
| C1 | 7 | 5 | 5.914 | 2.538 | 3.376 | 1.411 |
| B2 | 0 | 1 | 8.900 | 3.440 | 5.461 | 1.747 |
| B2 | 3 | 1 | 8.495 | 4.102 | 4.393 | 2.121 |
| B2 | 7 | 4 | 6.951 | 2.662 | 4.290 | 1.458 |
| C2 | 0 | 2 | 6.746 | 2.502 | 4.243 | 1.437 |
| C2 | 3 | 2 | 6.909 | 2.732 | 4.178 | 1.379 |
| C2 | 7 | 4 | 6.934 | 2.736 | 4.198 | 1.260 |

The position composition changes with early failure. A pooled median is not
proof of a repeatable improvement. Even at position 7, which passed every time,
app2 cycle means went 7.189→5.914s in pair 1 but 6.951→6.934s in pair 2.
A consistent end-to-end benefit beyond run variation was not established.

## Component evidence

| Run | app probe WG calls | app summed WG wall mean (s) | app2 probe WG calls | app2 summed WG wall mean (s) |
| --- | --- | --- | --- | --- |
| B1 | 18 | 0.230 | 32 | 0.328 |
| C1 | 9 | 0.063 | 16 | 0.247 |
| B2 | 18 | 0.248 | 32 | 0.427 |
| C2 | 9 | 0.040 | 16 | 0.162 |

Probe WG calls fell 18→9 and 32→16 in the sampled cycles; apply WG calls fell
10→8. Reduced subprocess work is real, but it did not satisfy continuity or
establish the primary latency result. Do not describe this as a shipped speedup.

## Review and verification

- Independent regression demonstrated RED on baseline, then GREEN on candidate.
- Focused race tests passed for fresh counter samples, strict numeric/peer
  validation, raw-buffer erasure, cancellation, TCP boundaries, route checks,
  surrounding evidence budgets and ownership. `go vet ./internal/relayapply`
  and diff checks passed.
- Independent review found no required code fixes. Peer-condition inversion and
  removal of raw-buffer clearing were both detected by regression tests.
- Performance acceptance failed. Full final CI and uninstrumented qualification
  were not run for this rejected candidate; focused tests are not full CI.

## Diagnostic follow-up

A failed continuity check preserves neither the exact input row nor its check
instant. Cleanup stores a later snapshot and waits up to 10s for active cycles.
In C1 position 0, a later row's FinishedAt precedes cleanup entry, but that does
not show what the failed check read or when the row became visible. Neither
false-positive dismissal nor a new product-regression claim is supported.
[#212](https://github.com/timo-kang/vpnctl/issues/212) tracks immutable failure-point
evidence, separately from later cleanup evidence, without weakening the gate.

## Evidence ledger

Local artifact roots, in run order:

- `/tmp/vpnctl-counter-baseline-1`
- `/tmp/vpnctl-counter-candidate-1`
- `/tmp/vpnctl-counter-baseline-2`
- `/tmp/vpnctl-counter-candidate-2`

Raw VM artifacts are private and can include keys/configuration/routes. Do not
publish them. This report and the following numerical comparison are allowlisted
summaries: `/tmp/vpnctl-counter-final-summary.json`. Each run has a separate
`-verified.json` manifest/isolation verdict. The fixed plan is
`/tmp/vpnctl-counter-measurement-plan.md`; the identical overlays are
`/tmp/vpnctl-counter-baseline-overlay.json` and
`/tmp/vpnctl-counter-candidate-overlay.json`. The diagnostic-only overlay source
is preserved in `/tmp/vpnctl-lease-maintenance-profile` and is not shipped.
