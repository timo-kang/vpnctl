# Fixed-source uplink and handoff qualification

Experiment-only branch; never merge this workflow into main. Existing PR CI
and all prior failures remain unchanged. This is functional integration and
resource-bound qualification, not a performance adoption claim.

Product and harness source: `63eccecea58fa8b82a410fc015a15439cc0efbc9`.
The original publisher time/withdrawal, fresh ownership and safety gates remain
unchanged. The source combines #230, its downstream consumers and #247 plus the
reviewed publisher/handoff integration fix. Its local race/vet/build and Python
regressions passed; this experiment provides the missing guest-kernel exercise.

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
