# Read-only ModemManager RF evidence (#26, #259)

Enable `modem_signals: true` only on an existing LTE uplink with an explicit,
canonical numeric `modem` index (for example `"0"`, not `"00"`). It defaults off.
It shares the existing uplink observation cadence (default 60 seconds, allowed
30..3600 seconds) and needs no separate process or database migration.

```yaml
node:
  uplink_observation:
    # Existing interval, targets and other required settings still apply.
    links:
      - {id: cellular, interface: wwan0, kind: lte, modem: "0", modem_signals: true}
```

`internal/modemsignal.Collector` runs only
`mmcli --modem INDEX --signal-get --output-keyvalue`, with `LC_ALL=C`. The existing
link/modem-state inventory runs first. Confirmed absence skips the signal read;
unknown modem state returns unknown RF evidence. Otherwise the signal read has
a two-second deadline inside the remaining link collection budget. Its result
does not replace link or modem connectivity state or change route selection.
The injectable `Read` provider must honor context and output bounds.

The collector never enables a modem, changes signal polling/thresholds, resets a
device, changes networks, or enables location/GNSS. It reads the configuration
already chosen by the deployment. [ModemManager separates signal reads from
polling and threshold configuration](https://www.freedesktop.org/software/ModemManager/api/latest/gdbus-org.freedesktop.ModemManager1.Modem.Signal.html).

## Values and time basis

Each LTE/NR5G radio has four optional numeric values: RSSI and RSRP in dBm,
RSRQ and SNR in dB. SNR is kept as SNR, not relabeled SINR. A radio dictionary
does not establish the current serving technology, cell ID or handoff event.
Support varies with modem and ModemManager version; missing fields are normal.
The field mapping follows the [mmcli signal implementation](https://raw.githubusercontent.com/linux-mobile-broadband/ModemManager/main/cli/mmcli-modem-signal.c)
and [machine-readable output keys](https://raw.githubusercontent.com/linux-mobile-broadband/ModemManager/main/cli/mmcli-output.c).

| State | Value | Meaning |
| --- | --- | --- |
| cached | present, including 0 | RF property is available, measurement time unknown |
| missing / not_reported | absent | Key absent or `--`; does not prove unsupported hardware |
| missing / no_modem | absent | Existing inventory confirmed configured modem absent |
| unsupported | absent | CLI explicitly reports no extended signal interface |
| unknown | absent | Invalid value, malformed output, unavailable collector, timeout, cancellation or output limit |

Every snapshot reports `source: modemmanager-signal` and
`measurement_time: unavailable`. `read_at` describes the read completion, never
the RF measurement. The API supplies no per-RF event timestamp, and the CLI read
prints stored signal properties; therefore freshness cannot be established from
the read alone. A generic `signal-quality.recent` flag is not applied to separate
RF fields. Reading unchanged values again does not establish a new measurement.

`read_stale` is set at age **>= three uplink intervals**, on backward read-clock
ordering, or when already marked stale. It is independent of the RF cache state:
`read_stale: false` still does not mean a fresh RF measurement. The raw read must
precede cycle completion and be within the existing seven-day admission bound.
Storage validates raw timestamps before UTC microsecond normalization; queries
do not refresh stored times. Source values/timestamps returned by queries detach
from stored data. Missing RF objects in legacy JSON remain absent.

Polling rate and RSSI/error-rate threshold settings are optional metadata, not
proof of measurement freshness. Rate 0 disables periodic polling; threshold
reporting may still be configured. This collector never changes either setting.

## Bounds and failure behavior

Command stdout is limited to 64 KiB and stderr to 4 KiB. The shared executor
retains deadline and process-group cleanup, discards partial stdout on failure,
and keeps raw output out of errors. The collector emits only fixed reason codes;
the unsupported-interface diagnosis requires the exact known CLI failure, not
an arbitrary error message. Other command failures remain unknown.

The parser retains only eight RF fields and three settings. Repeated recognized
keys are ambiguous and invalidate the output, even if identical. A malformed
individual number invalidates that field while other usable RF fields remain
cached. NaN, infinity and values outside [-1000,1000] are rejected; this is a
broad numeric admission limit, **not** a standardized RF operating range or
quality threshold. Values are never clipped or imputed. Polling/threshold
integers use unsigned 32-bit bounds. Unrelated device identity, phone numbers,
location and raw command output are not exported or logged.

Upgrade controller before enabling new agents: older strict JSON decoders reject
the additional `modem_signals` field. The feature remains opt-in. Fixture and
owned helper-process tests cover the command, time, payload and privacy contract;
they do not qualify real modem hardware, device-specific freshness or accuracy.

## Remaining prediction integration

Cached RF values are available in uplink raw snapshots for observation. They are
not copied into the zero-filled legacy `predictor.CellInfo`, and do not establish
handoff probability, bandwidth or NAT stability. A provider with trustworthy
device event times and explicit per-field validity is needed before live model
ingestion can claim measured RF age. Cell ID/serving technology, configuration
epochs, event coverage, privacy-safe trace and hardware qualification remain #26;
runtime and accuracy remain #27/#28.
