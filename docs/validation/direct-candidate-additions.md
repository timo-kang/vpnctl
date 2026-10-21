# Direct candidate additions (#261)

A delayed controller-ready peer used to cancel the entire in-flight direct
dataplane step, even when every existing candidate was unchanged. Cancellation
during a staged WireGuard mutation can leave an interrupted journal phase. The
next step then requires recovery of managed peers, disrupting unrelated paths.

The worker now lets its bounded step finish when the new candidate set contains
every previous candidate unchanged. New peers enter the next step and still
need the ordinary transport and two nonce proofs. Identity, key, VPN address,
endpoint, probe port, keepalive or generation changes, readiness withdrawal and
loss of the probe ticket still cancel and join the old work before replacement.
Shutdown, candidate age checks, the four-second step budget, proof deadlines,
cooldowns and the initial 60-second integration-test limit are unchanged.

`TestDataplaneAdditionPreservesInFlightVerification` reproduces the unnecessary
cancellation without touching the host network: an engine holds an authorized
step while a second candidate arrives. It fails on the old worker and passes
with the change. It also checks that the new peer appears only in the next
non-overlapping step. `TestDataplaneAdditionDoesNotMaskWithdrawalOrReplacement`
checks nine authority/input changes after an additive update. Existing tests
retain replacement/shutdown joining and conservative candidate clock checks.

```sh
go test -race ./internal/agent ./internal/directpath \
  -run '^TestDataplane|^TestCandidate|^TestDirect' -count=1
```

The original main CI failure is preserved in [#261](https://github.com/timo-kang/vpnctl/issues/261).
Its 32-node logs show 30 previous peers invalidated as the delayed `node-1`
appears, and an interrupted mutation/reset at node0. These observations are
consistent with the reproduced defect. They do not establish that it alone
caused all subsequent probe timeouts or the final two-direction convergence
failure. CPU contention, probe/ticket timing and the test's observation cost
remain separate hypotheses until qualified by controlled kernel comparisons.

Real kernel coverage uses the existing production and race direct-dataplane CI
matrix (2/3/8/32 nodes where configured), with all original packet, ownership,
fallback, restart and resource conditions. A passing rerun does not erase the
original failure or close the broader causal investigation.
