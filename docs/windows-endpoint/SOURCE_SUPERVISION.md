# Live source supervision and loss evidence

The console runtime samples successfully started collectors on a nominal one-second
loop. Sampling can be delayed by synchronous journal and native status-query work; this is
not a qualified maximum detection latency. Every source snapshot is included in
the next canonical health record. Changed loss/status facts produce a canonical
`gap` / `source_loss` record, stored through the same encrypted FULL/WAL journal
and protocol 2 delivery as observations. New gap facts also trigger health capture;
health exposes each source's pending durable gap acceptance. Startup explicitly records unknown
continuity, including the future-only Sysmon subscription's missing history.

ETW queries `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` with its owned session
handle, a separate output properties buffer and no session name. It never queries
or stops an unrelated session by discovery. Source `EventsLost`,
`RealTimeBuffersLost` and `LogBuffersLost` remain distinct decimal counters in
event/buffer units. Unavailable queries expose null counts and an error, never
zero loss. A falling counter means reset or wrap is unknown; no arithmetic wrap
estimate is emitted. ETW reports every unexpected ProcessTrace exit, including
success/cancellation/session disappearance when shutdown was not requested.

Both adapters count failed decoding/rendering and event-sink exceptions. These
counters are collector-lifetime totals. Normalization/serialization refusal now
has separate health accounting and decoded failure evidence; journal refusal also
throws to the collector and counts as a sink failure. These overlapping stage
counters require further complete accounting and must not be added as unique
lost observations. See [source facts](SOURCE_FACTS.md). A decode
counter does not prove that raw undecodable evidence was retained.

Sysmon counts strict-subscription error notifications, not missing event records.
Event Log provides no exact lost-event count here, so source counters stay null.
The continuity fault remains latched after an error; receiving another event does
not reconcile missing history. Its source becomes blind pending reconciliation.
Stopped consumers become blind even if another collector remains active. Process
and currently Sysmon-only file/registry/network domains reflect source availability.
Running sources remain degraded: activity and zero measured ETW loss do not prove
provider configuration, all security families, or continuous visibility.

Each gap includes source status, changes, unknown source-event range, and pending
reconciliation. Exact deltas are emitted only for available nondecreasing samples.
Initial nonzero totals or values restored after an unavailable query have null
deltas. Events, buffers and subscription notifications are never added together.
Pending canonical gaps retain identical serialized bytes/record IDs across journal
refusal. Each collector now keeps up to 128 reports/256 KiB of encoded gap data,
including the immutable front awaiting acceptance. Every observed sample advances
the measurement baseline independently of journal acceptance, preserving observed
statistics outages, stopped/resumed consumers and continuity-fault transitions
behind the pending front. Individual counter availability is also explicit;
restored zero totals have unknown deltas, and no delta bridges an observed outage.
The canonical pending copy, latest sampled status, JSON objects, temporary encoding
and allocator overhead are excluded from this encoded-data bound; it is not RSS.

If the report count/byte bound is exceeded, fixed omission-summary metadata retains
the number of omitted *reports* and their first/last sample uptimes. It is enqueued
in order when space becomes available, behind already retained reports and before
newer reports. Source status and missing native event/buffer counts remain null.
Health exposes queued reports/encoded bytes, accepted report count and total and
pending omissions separately. Omitted reports are not unique lost native events;
the summary does not restore source continuity. Unobserved transitions between
samples remain unknown. Pending history does not survive abrupt exit; emergency
reserve, durable fault intent, counter checkpoints and crash reconciliation remain
required. Allocation/native status-query and supervisor scheduling faults still
need qualification.

Regressions hold the front unchanged while newer statistics outage, restoration,
stop and resume samples arrive, then verify ordered consumption and unknown loss
deltas. Separate count/encoded-byte tests preserve explicit omission summaries.
An owned journal test refuses the original front at quota, accumulates an outage
and restoration, then reopens with capacity, accepts the same canonical bytes and
verifies exact three-record retention on another reopen. Manager contract tests
retain actual native history/omission fixtures through duplicate ingestion and
Detection transformation without manufacturing process identity or loss counts.

This is partial supervision, not complete loss qualification. Durable Event Log
bookmarks/replay, rollover/reset reconciliation, provider configuration/service
checks, native heartbeat/event occurrence age, automatic source recovery,
queue/admission/stage accounting, immediate-priority delivery, storm/error
simulation and OS compatibility qualification remain open.

Primary Windows API references:

- [ControlTrace query](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew)
- [EVENT_TRACE_PROPERTIES counters](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
- [Strict Event Log subscription callbacks](https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events)

Live probes are explicitly opt-in, outside CTest:

```powershell
build-verify-x64\officer-source-supervisor-tests.exe --probe-source etw
build-verify-x64\officer-source-supervisor-tests.exe --probe-source sysmon
```

They create and close only their own subscription/session, sample for two seconds,
and report unavailable sources with exit 2. They do not install Sysmon, alter
configuration, elevate the process, or infer a successful source test from access
denial. This laptop's current non-elevated probes both reported Access denied;
successful live queries and fault injection are therefore still unqualified.
