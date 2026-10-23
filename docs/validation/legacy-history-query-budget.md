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

The seven-day legacy query uses a stream-bounded primary-tree scan in ID order.
Unary `+` disqualifies the time index for this query shape; stored timestamps
and bound parameters are integers. Shorter windows retain the selective time
index and timestamp ordering. No schema migration, extra index, cache, storage
budget increase or change to tiered queries is required.

Counts, sums and exact percentiles do not depend on arrival order. Only jitter
needs a time-ordered population, so the full-window query saves compact pairs
of timestamp and RTT, using the existing negative sentinel for failed/unknown
outcomes. Sorting these pairs avoids SQLite sorting complete row records.
Equal timestamps remain ambiguous barriers regardless of ID order; failures,
unknowns and measured zero RTT retain their original meanings.

The sample buffer is reused between streams and checked against the existing
four-million-row limit before each append. Each pair occupies sixteen bytes;
unsorted streams may additionally need one equally sized merge buffer. At the
row limit these two populations occupy 128 million bytes, before slice capacity
and allocator overhead, in addition to the existing percentile/result buffers.
Sorted runs are at most 4,096 samples. Merge copying, merging and aggregation
check cancellation between bounded batches, preventing an entire multi-million
sample sort from deferring cancellation.

Full-window requests over a sparse or historical interval can visit rows outside
that interval before filtering; only the largest allowed window uses this
strategy. Query admission, database population and the eight-second deadline
remain unchanged. Results retain a single read snapshot, `(start,end]` bounds,
exact percentiles and ordered jitter. Cancellation or capacity failure returns
an error, never partial success.

The plan regression guards against repeated secondary lookups or a SQLite sort
for full retention, while protecting shorter time-index scans. Behavioral tests
cover reverse/random ID order, duplicate timestamps, unknowns, failures, zero
RTT, bucket boundaries, node filtering, cross-stream isolation and cancellation.
Full-retention buckets are compared with independently queried indexed daily
windows. Sort tests preserve the complete value multiset across run boundaries
and exercise cancellation after work has started.

Before/after comparisons use identical retained data and verify a SHA-256 of the
complete serialized buckets. The existing full-scale test keeps its eight-second
query, sixty-second cleanup and one-GiB storage gates. Query-only measurements
cannot qualify restart, cleanup or the full lifecycle; unchanged full-scale
remote validation and exact-head CI are required before completing this fix.
Results are not a latency guarantee for every robot or controller.

SQLite documents [WITHOUT ROWID primary trees](https://www.sqlite.org/withoutrowid.html)
and the [unary-plus alternative to forcing an index](https://www.sqlite.org/lang_indexedby.html).
