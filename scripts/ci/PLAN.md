# Fixed-source uplink and handoff qualification

Experiment-only branch; never merge this workflow into main. Existing PR CI
and all prior failures remain unchanged. This is functional integration and
resource-bound qualification, not a performance adoption claim.

Product and harness source: `2fd9b52858ea95a8505833fab78b428c49344dc9`.
The original publisher time/withdrawal, fresh ownership and safety gates remain
unchanged. The source combines #230, its downstream consumers and #247 plus the
reviewed publisher/handoff integration fix and #248 observation-cache lifetime
repair. The original and reacquired Engines restore live kernel checks after
observation. Local race/vet/build and the focused lifetime regressions passed;
this experiment exercises that repaired composition in the guest kernel.

The earlier source `63eccec` completed all ten trials in run 38838720264; four
passed and six failed. All 8-candidate capacity profiles failed, including API
off. Both actual app profiles passed on that earlier source only. The encrypted
evidence remains intact. This new source includes a required correctness repair
that changes which live checks execute; it is not an unchanged-source retry.
No broader capacity or performance improvement is assumed. The same predeclared
schedule is kept to expose the impact of restoring those checks, not to select
only passing profiles. Compare outcomes with their source/image identities;
these separate builds cannot establish a matched performance improvement.

One disposable GitHub-hosted ubuntu-24.04 runner builds race binaries and the
Docker image once via the original `scripts/test-vm.sh`. The first scheduled
trial prepares a single guest base image. All later trials reuse that exact
read-only image and executable bytes, verified by SHA-256 before/after each
trial and against each observer manifest. Every exercise uses a fresh writable
overlay and fixture state. Never rebuild or retry after an initial failure.
After each trial, discard only its owned runtime disks after Docker confirms
that its named container has terminated; retain logs and reports. The fixed
base image remains unchanged. Unconfirmed cleanup is an infrastructure failure.

Fixed schedule, once each, without retrying to obtain a pass:

| Order | Profile | API load |
| --- | --- | --- |
| 1–2 | 4 candidates, split CPUs | off, on |
| 3–4 | 8 candidates, split CPUs | on, off |
| 5–6 | 8 candidates, rebuild, split CPUs | off, on |
| 7–8 | 8 candidates, shared CPU | on, off |
| 9–10 | actual Go/Python application recovery, 4 then 8 candidates | existing application profile |

Robot quota is 0.5 CPU throughout. Split profiles use two guest/outer CPUs with
verified role placement; shared profiles use one CPU. Container limits stay at
2 GiB, no swap, no network, no capabilities; guest memory stays at 768 MiB. API
load clients retain the existing server/measurement role and do not consume the
robot quota. First preparation has a 35-minute watchdog; later trials each have
25 minutes. Workflow execution is limited to 270 minutes, job to 300 minutes,
leaving time to seal partial evidence. A timeout means failure/incomplete.

All original payload, lease, observed-age, frozen-publication, CPU placement,
API admission/load-coverage and application authorization/recovery checks stay
enabled. A zero exit cannot pass without one matching completed and qualified
observer verdict. Every failure is retained, and later planned trials still run.
If preparation is unavailable, later attempts explicitly record missing image
evidence instead of silently rebuilding it. Both sides of an off/on pair must
pass; a failing baseline does not excuse a failing load trial. A single pair
cannot establish hardware capacity or a general latency improvement. App recovery
is measured separately per app; watchdogs are not deployment recovery targets.

Network/kernel operations occur only inside owned disposable guests. Device ACL
setup is limited to the GitHub-hosted runner. No local host networking, power,
clock or kernel changes are made. Detailed raw evidence, logs and retained
executables are encrypted before artifact upload; the private key stays off CI.
Do not print raw measurements into public logs or PR conclusions.
