# Legacy full-retention query budget

The original main run for [#265](https://github.com/timo-kang/vpnctl/issues/265)
passed the twenty-million-observation tiered transition, then exceeded the
unchanged eight-second legacy query deadline at 3,870,720 probes. The same tree
had previously completed that seven-day query in 6.16 seconds. Both original
results are preserved; a later pass does not replace the failure.

Query-only profiling of the original fixed population showed over half the CPU
samples in SQLite B-tree lookup. The time-range index identifies each sample,
then SQLite looks up its RTT and outcome in the WITHOUT ROWID primary tree.
For a full-retention request this repeats a lookup for nearly every row.

The seven-day legacy query now permits a stream-bounded primary-tree scan and
an explicit timestamp/ID sort. Unary `+` disqualifies the time index for this
one query shape; stored timestamps and bound parameters are integers. Shorter
windows retain their selective time-index scan. There is no schema migration,
extra index, cache, increased storage budget or change to tiered queries.

This trades sorting for repeated point lookups. Full-window requests over a
sparse or historical interval can visit rows outside that interval before
filtering; only the largest allowed window uses this strategy. The database
population, query admission and eight-second cancellation budget still bound
the work. Query results retain the same single read snapshot, `(start,end]`
boundaries, exact percentiles, unknown/failure distinctions and ordered jitter.
Cancellation or capacity failure returns an error, never partial success.

The plan regression protects both the full-retention primary scan and shorter
time-index scans. Behavioral tests use reverse arrival, non-time-ordered IDs,
duplicate timestamps, unknowns, failures, a measured zero, bucket boundaries,
node filtering and cancellation. The existing full-scale test keeps its
eight-second query, sixty-second cleanup and one-GiB storage gates.

Before/after comparisons use identical retained data and check a SHA-256 of
the complete serialized buckets. Local measurements establish the contribution
of the redundant lookups; they are not a latency guarantee for every robot or
controller. Exact-head CI remains the merge gate.

SQLite documents [WITHOUT ROWID primary trees](https://www.sqlite.org/withoutrowid.html)
and the [unary-plus alternative to forcing an index](https://www.sqlite.org/lang_indexedby.html).
