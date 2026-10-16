# Fixed-source application failure evidence validation

Experiment-only branch; never merge this workflow into main. Existing PR CI
and all prior failures remain unchanged. This run validates diagnostic capture
and original app contracts; it is not a performance adoption comparison.

Product and harness source: `9c0700fd393657a51d7b696eb6ba834b0c713a4d`. It adds #249's worker
assertion tail and bounded graceful app failure cleanup to `2fd9b52`. The diff
changes only the harness, regression tests, CI regression selection and docs.
Product code, client connect/I/O deadlines, retry behavior, CPU budgets, all
15 original phases, connection-preservation and approval gates remain unchanged.

Earlier run 38847391806 completed all ten planned invocations at `2fd9b52`:
three passed and seven failed, without cancellation, retry or infrastructure
error. Four-candidate API-off/on and actual apps passed; all six eight-candidate
capacity trials failed. Actual eight-candidate apps failed api_outage_payload
after baseline/api_outage. Subsequent phases were not executed. Connection
counters alone cannot identify why a socket was replaced; missing worker and
final request evidence motivated this harness fix. Those results stay intact.

Fixed schedule, once each, without retrying to obtain a pass:

| Order | Profile | Purpose |
| --- | --- | --- |
| 1 | Actual Go/Python applications, 4 candidates, split CPUs | Preserve previously passing behavior |
| 2 | Actual Go/Python applications, 8 candidates, split CPUs | Capture failure assertion and final request events if failure recurs |

Do not rerun the unchanged capacity matrix. A passing app8 trial would qualify
only this execution's original app contracts and would leave VM failure-capture
coverage incomplete; it cannot erase the earlier failure or establish its cause.
An app failure remains a failure after cleanup. Inspect unfinished phase markers
and original worker exit, bounded/redacted worker tail, per-app client_cleanup,
final events/counters and last progress. Events emitted during cleanup are
strictly diagnostic and must never complete or qualify the original phase.
If an app cannot drain within 12 seconds, retain its forced/failed state and
missing evidence explicitly. Do not convert incomplete evidence into success.

One disposable GitHub-hosted ubuntu-24.04 runner builds race binaries and the
Docker image once via the original scripts/test-vm.sh. First trial prepares one
guest base image; second reuses exact read-only image and executable/module bytes
verified by SHA-256 before and after each trial. Fresh writable overlays and
fixtures per trial. Never rebuild or retry after an initial failure. Only remove
an invocation's owned runtime after Docker confirms its named container stopped;
retain reports/logs. Unconfirmed cleanup is an infrastructure failure.

Both profiles use two guest/outer CPUs, verified role placement, robot quota
0.5 CPU, container 2 GiB without swap/network/capabilities and guest 768 MiB.
No API load flood is enabled; the actual apps still consume their APIs normally.
First preparation has a 35-minute watchdog, second trial 25 minutes. Workflow
execution is limited to 75 minutes, job to 90 minutes, with time to seal partial
evidence. Timeouts mean failure/incomplete, not an app recovery SLO.

Every planned trial executes despite a preceding failure. A zero exit requires
one matching completed and qualified observer verdict. Preserve image/source/CPU
identity and original app validator. A single pair cannot establish hardware
capacity, latency distribution, API load qualification or general root cause.

Network/kernel operations occur only inside owned disposable guests. Device ACL
setup is limited to the GitHub-hosted runner. No local host network, power, clock
or kernel changes. Raw detailed evidence, logs and retained executables are
encrypted before artifact upload; the private key stays off CI. Do not print raw
measurements into public logs or PR conclusions.
