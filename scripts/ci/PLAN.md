# One-runner matched CI investigation (PR236)

Generation 2 is a separate run after run38492657318 completed naturally with an
incomplete comparison matrix. That original run and every failure remain retained;
no attempt is rerun or substituted. This generation keeps the same fixed schedule
and product criteria. Only disposable-runner KVM access preparation changes: capture
device/ACL evidence, re-establish the runner user's ACL when needed immediately
before each scheduled invocation, and capture access again after it ends. A failed
preparation is retained as an infrastructure failure; a started test is never
retried. No claim is made about which external actor removed access. No local host
permissions are changed.

This experiment branch is not a replacement reliability pipeline and is not
intended for merging into main. It runs only by manual dispatch. No product or
original fixture code is changed. Local preliminary results are not adoption
evidence and are not published here.

A = 73a5d5f1ad7ebf24d6d28503f24e43c39ad19d40 (latest main at preregistration).
B = d5d7877d1ebb783359b03c74e543866a04de3c46 (PR236).

One GitHub-hosted ubuntu-24.04 job, one image built once from the common A/B
harness then pinned by immutable image ID; verify all embedded harness hashes.
Build each source cleanly, race=1, GOMAXPROCS=2, Go -p=2. Whole VM container
1 CPU, robot0.5 CPU, shared layout, 2GiB container/768MiB guest. Original payload,
lease, freshness and publication criteria unchanged, including 10s max proof
age, 15s minimum steady window and >=3 applied cycles per app. Host clocks and
power are never adjusted; KVM access changes only on the disposable CI runner.

Four paired repetitions: A B / B A / A B / B A. Cases are 4 then8 in pairs1/3,
8 then4 in pairs2/4. Eight invocations, sixteen fresh VM exercises, forty-eight
position fixtures (4:0/1/3, 8:0/3/7). Never replace/retry an attempt or extend
this schedule for green/significance. Continue the fixed schedule after test
failures; retain infrastructure failures as invalid/missing evidence. Do not
cancel running experiments. Existing runner timeouts remain; job timeout330m
and test-step timeout300m leave time to seal evidence. Timeout means incomplete.

Primary evidence: preserve all original gates/first failures and independently
replay frozen publication windows. Analyze A/B separately by path count,
healthy position and app, using one fixture summary per replicate. A failed
candidate gate remains a merge blocker even if baseline also fails.

Common latency: app-only first_payload_seconds (app2 unmeasured); per-role
maximum operation duration, consecutive completion/receipt intervals, and proof
age at completion/receipt. Successful operation StartedAt excludes CLI admission.
Use frozen publication rows with index>=baseline_count and qualification.start
<received_at<=qualification.end after validating ALL input boundaries/order.
Use baseline_count-1 only as predecessor for consecutive intervals. Missing or
invalid records/window/partner => incomplete, never zero or silent exclusion.
Do not include later diagnostic/cleanup rows. Completion is not publication;
receipt is an upper bound. Do not compare old/new diagnostic total scope.

CPU: QEMU+observer whole-container usage delta, including boot/setup/three
positions. With before read [b0,b1], after read [a0,a1], elapsed lies within
[a0-b1,a1-b0]. CPU rate bounds = [delta/(a1-b0),delta/(a0-b1)]. Compare B-A
interval bounds. Robot counters have no precise matching time interval and do
not establish per-robot utilization. Retain them as cumulative context only.

Preregistered investigative margins (not product SLOs): latency flag when B-A
>max(100ms,5% of A). CPU flag if lower delta bound>0.02CPU; uncertain if interval
straddles0.02. Repeated >=3/4 same-stratum flags warrant suspected regression,
not causal proof. Any isolated flag/high variance remains inconclusive; never
claim no significance proves equivalence. Bounded no-observed-regression needs
all candidate original gates passing, complete provenance/replay and zero flags.
Four pairs cannot establish universal non-inferiority or rare-event safety.
Do not reset failed PR checks or relax criteria based on these results.

Retain original results/logs and deduplicated executable bytes with hashes.
Prove invocation work using before/after directory inode inventories; reclaim
only a single newly created private owned directory after retaining all available
executable bytes. This also handles pre-manifest image failures without letting
partial disk images consume space needed by later attempts. Ambiguous ownership
is retained as an infrastructure failure, never guessed. Raw evidence is encrypted with the committed one-experiment public key;
the private key remains off CI. Create a 0600 plaintext archive under the 0700 evidence root; promote the private
partial ciphertext to the upload path only after successful encryption and remove
the plaintext archive. Reject archive links. Upload only encrypted evidence. No raw metrics,
credentials, verdicts or unadopted performance report is published to PRs/issues.
