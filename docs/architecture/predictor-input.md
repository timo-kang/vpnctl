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

Remaining #26 work: target-uplink service adapter, cellular signal collector with
explicit unsupported/no-modem states, timestamped route/handoff/NAT coverage and
privacy-safe trace recording/replay. This increment does not complete #26, #27,
#28 or the M4 gate.
