# Direct convergence log snapshots

The initial direct convergence check reads each visited agent log once per poll
and derives all of that agent's latest peer states from that read. Previously,
it re-read the whole file for each destination: up to 992 reads for 32 agents.
Besides added observer load within the shared CPU budget, this could combine
incompatible states: one read with peer A active/B in cooldown and another with
A in cooldown/B active could incorrectly satisfy both checks.

The snapshot is per agent, not atomic across the mesh. There is no state cache
between polls. Missing peers, non-active latest states, read errors, malformed
direct records and incomplete trailing records cannot satisfy convergence.
An incomplete write is retried on the next poll. The first failing direction
is still reported, in the same traversal order.

This changes only the initial integration-test observer. It does not alter the
agent, direct proofs, CPU/memory allocations, 60-second initial deadline,
100-millisecond polling interval or later packet/fault/fallback/restart gates.
The later two-peer fault watchdog retains its existing reader. A log snapshot
does not establish a new freshness, application recovery or deployment SLO.

`TestDirectSnapshot*` covers read counts at 2/3/8/32 nodes, incompatible reads,
latest withdrawal, exact peer identity, missing evidence, partial writes,
malformed records, read errors and re-reading after truncation. The existing
direct production/race CI matrix runs these tests with its kernel tests.

```sh
go test -race -tags=integration ./tests/integration -run '^TestDirect' -count=1
```

The preserved #261 failure at its original cutoff still fails with
`0 -> 3: handshaking` under both observers. Fixed successful log snapshots also
remain successful. This guards against rewriting a failed experiment as a
pass; lower observer cost alone does not establish the cause of the original
convergence timeout. See [#263](https://github.com/timo-kang/vpnctl/issues/263).
