# Experimental app connection-loss diagnostics

This branch is an experiment, not a merge candidate or an app qualification.
The original 15-phase app trial and its limits remain available unchanged when
no diagnostic mode is requested. Diagnostic cases are explicitly marked
`diagnostic_only_no_qualification`; their shorter windows never satisfy that
trial's validator.

All cases use eight candidates, both real apps, split two-vCPU guests, and the
same race binaries/image with fresh VM overlays. Test only two interventions:
API socket rename versus no fault, and robot quota 0.5 versus 1 CPU. Both apps,
selectors and robot supervisor stay on guest CPU 0; controller/relays/measurement
stay on CPU 1. Increasing quota changes the whole robot role's budget, so an
improvement would not identify which robot process caused delay.

After a healthy baseline each case observes 45 seconds following the action.
Require continuing authenticated responses, the expected API state and the
same initial connection counters. Keep failures, incomplete phases and original
worker exit. A 75-second watchdog is not a deployment recovery SLO. Do not
increase client one-second connect/I/O deadlines, the server two-second read
limit, observation age, approval lifetime or any safety gate.

A positive control pauses only the Go app child in the disposable guest for
three seconds, always resumes it, then uses the same window/assertion. It should
expose the server idle-close mechanism and deliberately fail connection
preservation. Its expected failure must retain both apps' final histories via
#249 cleanup, the assertion tail and the server close record. This cannot prove
that the original unforced incident had the same cause.

Server diagnostics are opt-in, at most 512 close records plus one truncation
marker. They retain stage, error category, synthetic target address, request
count and guest boot-clock timestamps; no peer address, nonce, key material or
raw exception string. The close timestamp is observed after closure, not an
exact kernel transition. Client events, sampled route/supervisor logs and role
CPU counters accompany it. Missing/truncated diagnostics remain explicit.

Hypotheses and distinguishing evidence:

- API coupling: compare rename/control at the same quota. Actual payload loops
  have no API input and API retry sleeps, so no direct close path or busy loop
  was found by code review. This does not exclude shared resource effects.
- Robot CPU contention: compare quotas within the same API condition; inspect
  cgroup usage/throttle/pressure deltas. This alone cannot separate app scheduling
  from selector/supervisor work, nor certify deployment hardware.
- Server idle close: require a server read timeout after its last response and
  correlate the target/app event timeline. A loopback TLS test reproduces this
  with no VPN or API; the controlled guest pause tests the complete path.
- Transient route/approval enforcement: correlate failed client requests with
  route/supervisor records. These are sampled states; a missing denial record
  does not prove no short-lived packet drop occurred.
- Environment/order effects: one immutable image, fresh overlays, reversed cell
  order and two prespecified trials per cell limit some confounders. Two trials
  do not establish a failure-rate distribution or exclude intermittent effects.

Never run guest setup or process-pause actions on this host. Raw trial evidence
is encrypted before upload. The source and the runner schedule are fixed before
the remote experiment begins; do not stop/retry individual failed cells.
