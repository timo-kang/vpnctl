# Measured predictor inputs (#26, #255)

`internal/predictorinput.BuildProbes` converts one M2 probe stream into a
bounded, deterministic `predictor.Observation`. It is an in-process data boundary,
not a background collector or predictor runtime. It performs no network, disk,
route or modem operations. #27 owns runtime/forecast publication; #28 owns model
accuracy validation. Forecasts do not change current availability or robot motion.

## Identity and evidence

The caller supplies an authenticated node's `history.Stream` and its individual
`history.Observation` records. Every record must match source, peer, path, relay
and uplink exactly. The node ID comes from the authenticated envelope, not the
record body. The builder validates shape, not the caller's authentication.

A monitor-overlay probe measures a VPN **peer**. It is not evidence about a target
server, nor independent proof of a selected relay/underlay. M2 `path: unknown`
remains unknown; route labels are reporter claims. Target service/TCP-connect
observations require their own adapter and stream identity. These populations
must not be merged just because both have millisecond fields.

## Windows, units and freshness

Configuration is explicit: `RTTWindow`, `LossWindow`, `Bucket`, and `MaxAge`.
Both windows must be positive and at most two minutes. Bucket width is at least
one microsecond and no larger than either window. Freshness is positive and no
larger than either window. These are feature ingestion budgets, not app SLOs or
the selector's authority deadline.

| Feature | Units and population | Reduction | Missing/unknown handling |
| --- | --- | --- | --- |
| RTT | ms, finite [0,60000], successful probes only | Latest outcome in each UTC bucket; retain RTT only when that outcome is successful | Latest failure has no RTT; latest unknown suppresses the current RTT input |
| Probe failure ratio (`SignalLoss`) | percent [0,100], failed completed probes / completed probes in the bucket | One ratio per bucket | Any unknown in a bucket makes that bucket unusable; unknown is never a failed probe or an implicit successful one |
| Bandwidth | Mbps | Not collected by this adapter | Missing; byte throughput is not available bandwidth |
| Handoff probability | [0,1] | Not collected by this adapter | Missing; no modem/event collector does not mean zero handoffs |
| NAT stability | [0,1] | Not collected by this adapter | Missing; an empty remap list does not prove stability |

Windows are **(tick - window, tick]**, using event time, never receipt time.
Future/zero timestamps, malformed records and out-of-range numbers are rejected,
not clipped. Every input is validated before canonical M2 microsecond truncation;
a future sub-microsecond sample cannot round back into validity. Times are
normalized to UTC with no process-local monotonic component. A production caller
must establish clock alignment before joining remote sources. This wall-time
builder supplies no live approval, lease or route-authority proof.

Buckets use UTC `time.Truncate(Bucket)` boundaries, left inclusive and right
exclusive. The current partial bucket is included. Output sample time is the
latest contributing event time, not the bucket edge or the read time. Loss
buckets whose lower edge is at or before the window cutoff are omitted entirely:
removing an expired failure/unknown cannot fabricate a new healthy ratio without
a new event. An otherwise fresh window with only such a partial bucket reports
`missing/partial_window_bucket`. Older
unknown loss buckets remain gaps; metadata records their unknown counts. At the
same event time, any unknown prevents current confidence, and a failure prevents
an RTT claim, regardless of ID ordering. Successful RTT ties use stable ID order.

An age **equal to** `MaxAge` is stale. Stale/unknown/missing dimensions carry no
predictor samples. Each feature retains source, state, bounded reason,
latest source timestamp/age, unique input count and unknown count. Valid RTT 0 ms
and failure ratio 0% are retained as measured zeros. A tick with neither usable
RTT nor failure-ratio data returns `Ready: false` and
`no_usable_probe_measurement`, with per-feature reasons. `Ready` means data is
available, not that a model is trained, accurate or operationally qualified.

## Sampling and retention

Use the source's actual cadence. The live monitor currently defaults to 5 seconds;
this builder does not raise that rate. For example, a 5-second source can use
30-second RTT/loss windows, 1-second buckets and a separately selected 12-second
freshness budget. That yields sparse real samples, not a manufactured 1 Hz or
10 Hz trace. Model-specific cadence/warmup requirements belong to #27/#28; an
AR model must not silently treat irregular timestamps as a qualified uniform
sampling sequence. No outlier smoothing or statistical winsorization is applied.

At most 1200 input records are accepted per call, **before** duplicate removal.
Oversized input is rejected; it is not silently truncated. Identity/pointer copies
are detached in the output. The builder retains no state between calls, performs
no raw trace recording, and returns at most one sample per nonempty usable
bucket. M2's existing seven-day admission bound still applies. Query/pagination
and retention belong to the caller and existing history storage; repeated reads
never create samples or extend their age.

Identical canonical duplicate IDs are idempotent. Reuse with different content is
`history.ErrConflict`. Sorting by canonical event time then ID makes shuffled
inputs deterministic. Replay must supply only events at or before its tick; a
future event is an error, not information available to the model. Stream IDs and
other metadata are private evidence, not a privacy-safe export format.

## Predictor compatibility

Measured observations always set the new `Known` mask. All four existing model
implementations preserve unavailable dimensions through composition, with point,
interval and health zeroed. A consumer must use health/input metadata to interpret
those zero placeholders, not advertise them as measured values. The NAT model
cannot couple an unavailable handoff forecast into a known NAT dimension.
An explicitly known but absent scalar history is invalid. At least one usable
RTT, loss or bandwidth measurement is required by the existing model baseline.

`Known: nil` retains the old synthetic/research calling convention. It is not a
production ingestion path. No current route or app API consumes forecasts.

## Validation and remaining #26 work

Tests cover successful zero, completed failure, unknown/stale input, window and
expiry equality, mixed stream rejection, future timestamps, invalid values,
idempotent duplicates/conflicts, simultaneous conflicting outcomes, deterministic
reordering, detached outputs and read-time aging. All model compositions are
checked for missing-dimension propagation, including cold-start AR fallback.
Mutation checks must detect removal of freshness or unknown-input guards.

Remaining #26 work: target-uplink window/model integration, cellular signal collector with
explicit unsupported/no-modem states, timestamped route/handoff/NAT coverage and
privacy-safe trace recording/replay. This increment does not complete #26, #27,
#28 or the M4 gate.

## Target service source adapter (#257)

`BuildUplinkService(ServiceStream, Snapshot, tick, maxAge)` returns one target's
service evidence. It is separate from `BuildProbes`: node/target/protocol identity
does not identify a peer probe or one relay route. Node authentication belongs to
the caller. Endpoint/probing-policy changes under a reused target ID require a
new caller-managed configuration epoch before building histories; snapshots do
not currently carry that epoch. No window aggregation or forecast is introduced.

`Target.service_started_at` and `service_completed_at` bound the entire service
Probe call, including resolution/retries. They exclude an earlier relay probe,
later WireGuard transport inspection, and waits for other link/target workers.
The result is available only after completion. `Feature.ObservedAt` is the start
and `AgeNS` is tick minus start: a slow completed attempt or delayed delivery
cannot rejuvenate older evidence. Equality with maxAge is stale. maxAge must be
positive and at most two minutes; the existing source expiry (three collection
intervals), or an explicit stale query flag, can expire the result sooner.

The two optional timestamps must either both be absent (legacy) or satisfy
`tick - 7 days < started <= completed <= cycle.At <= tick`. Raw timestamps are
validated before storage normalization to UTC microseconds. Partial, reversed or
future timestamps are errors. Legacy snapshots remain readable and ingestible,
but the adapter returns `missing/service_time_unavailable` and no measurement;
cycle completion is never substituted for unavailable attempt timing. A missing
target is `missing/target_not_collected`; a protocol mismatch is an input error.

| Protocol | Duration kind | Meaning of the existing service `rtt_ms` |
| --- | --- | --- |
| tcp | tcp_connect | Successful socket connect and local socket setup elapsed time |
| tls | tcp_connect_tls_handshake | Connect, local trust setup and TLS handshake elapsed time |
| udp-echo | udp_socket_echo | UDP socket setup plus nonce-checked echo elapsed time |

These finite [0,60000] millisecond durations exclude prior DNS/failed-IP retries
and are not the full attempt interval. They remain named `DurationMS` in the
adapter, with explicit kind, instead of being silently placed in peer
`RTTHistory`. No packet-loss ratio is inferred from a single service result.
`Ready` means usable evidence, including completed failures (`Success=false`,
no duration). Successful duration zero is valid. Unknown/stale/missing results
have neither success nor duration; unknown retains its bounded collector reason.
Bandwidth, cell, handoff and NAT values are not synthesized.

The adapter is stateless, does no I/O, and reads at most the bounded snapshot's
eight links/four targets. Returned times/numbers are detached from the input.
It retains the cycle ID/time, interval and cumulative process-local `Dropped`
counter for provenance. Drops do not establish exact event coverage; reset/epoch
handling remains pending. Repeated ticks never create a fresh observation.

Raw snapshot times survive JSON ingestion, compressed persistence, restart,
latest and history queries. SQL summary windows still use **cycle** timestamps,
so their averages are not a substitute for event-time predictor input. Consumers
must fetch raw snapshots and handle query truncation rather than infer missing
attempts. This remains private evidence, not a privacy-safe trace export.

Upgrade the controller before agents: new controllers accept legacy records,
but old controllers strictly reject unknown JSON fields from a new agent. No
database migration is required; optional fields live in the existing payload.
These wall-clock fields do not provide clock synchronization, live leases or
route authority and do not change the app routing API or its freshness gates.
