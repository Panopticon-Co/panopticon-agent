# Phase 2: live process collection

## Outcome

Officer now has two independent live Windows telemetry sources:

- `EtwProcessCollector` uses the raw ETW controller, consumer, and TDH APIs to
  receive `Microsoft-Windows-Kernel-Process` event ID 1.
- `SysmonEventCollector` uses `EvtSubscribe` to receive future Sysmon event ID 1
  records from `Microsoft-Windows-Sysmon/Operational`.

Both collectors implement `TelemetryCollector` and publish the same owned
`RawProcessEvent`. Neither collector knows about enrichment, JSON, storage,
transport, or detection.

```text
ETW + TDH ---------\
                    -> RawEvent callback -> enrichment -> normalization -> NDJSON
Sysmon + EvtSubscribe/
```

## Source adapters and event schemas

Panopticon schemas describe semantic events, not acquisition products. ETW and
Sysmon process creation both populate the `process/start` schema. A future
network connection will populate a separate `network/connect` payload, whether
it came from ETW, Sysmon, or another source.

Each future event type should have:

1. A strongly typed raw contract containing observed facts.
2. An optional enriched contract containing derived facts.
3. A normalized Panopticon payload and versioned JSON Schema.
4. One or more independent source adapters that populate the raw contract.

This avoids a giant object containing unrelated nullable process, network,
file, registry, and DNS fields.

Schema 0.2 adds a required `source` object. Two observations of the same process
can now share `process.entity_id` while retaining distinct `event.id` and source
provenance.

## Raw ETW API sequence

ETW has three roles: a provider writes events, a controller configures a trace
session, and a consumer reads the events. Officer is both controller and
consumer; `Microsoft-Windows-Kernel-Process` is the provider.

The collector uses the APIs in this order:

1. `StartTraceW` creates the named real-time session and returns its controller
   handle. The session is a kernel-owned routing and buffering object, not the
   consumer itself.
2. `EnableTraceEx2` enables the process provider on that session with the
   process keyword. Starting a session alone does not select a provider.
3. `OpenTraceW` opens the session as a real-time consumer and returns a separate
   processing handle. It also registers Officer's `EventRecordCallback`.
4. `ProcessTrace` enters the delivery loop and invokes the callback for each
   record. It blocks while the live session remains open, so Officer runs it on
   a dedicated worker thread rather than blocking startup and Ctrl+C handling.
5. Shutdown disables the provider, calls
   `ControlTraceW(EVENT_TRACE_CONTROL_STOP)`, calls `CloseTrace` on the consumer
   handle, and joins the worker. The collector destructor repeats the stop path
   safely, so normal returns and partial startup failures release owned state.

The controller and consumer handles represent different responsibilities and
must not be confused. Stopping the session tells Windows to stop producing into
it; closing the processing handle releases the consumer and allows the blocked
`ProcessTrace` call to return.

## `EVENT_RECORD` and TDH decoding

Windows passes a pointer to `EVENT_RECORD` only for the duration of the
callback. Its `EventHeader` identifies the provider, event ID, version, level,
keyword, timestamp, process, and thread. Its user-data pointer contains the
provider-specific payload, and `UserContext` points to the collector instance
registered through `EVENT_TRACE_LOGFILEW::Context`.

Officer does not cast the payload to a hand-written struct. Provider manifests
can evolve, so the collector asks Trace Data Helper (TDH) to interpret the
record:

1. Call `TdhGetEventInformation` with no buffer to obtain the required size.
2. Allocate that buffer and call it again to obtain `TRACE_EVENT_INFO`.
3. Verify each required top-level property's declared input type.
4. Call `TdhGetPropertySize`, allocate an owned byte buffer, and call
   `TdhGetProperty` by property name.
5. Convert `FILETIME` ticks and UTF-16 strings, then copy all facts into an
   owned `RawProcessEvent` before returning from the callback.

No `EVENT_RECORD`, TDH metadata, or Windows-owned payload pointer escapes the
callback.

## Kernel process event ID 1 mapping

The provider GUID is `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`. The installed
Windows provider manifest exposes process-start event ID 1 in versions 0
through 4. The collector deliberately reads the stable fields common to every
version:

| ETW property | Type | `RawProcessEvent` field |
| --- | --- | --- |
| `ProcessID` | `UInt32` | `pid` |
| `CreateTime` | `FILETIME` | `process_start_time` |
| `ParentProcessID` | `UInt32` | `parent_pid` |
| `ImageName` | Unicode string | `executable` |

Later versions add flags, image checksum/timestamp, package identity, process
and parent sequence numbers, token elevation, mandatory label, and security
mitigation fields. They are not silently inserted into the process/start
contract; useful fields should be added through an explicit contract and
schema revision. This event does not expose the command line or owner SID, so
those fields remain absent for ETW rather than being guessed.

## ETW lifecycle

The ETW collector owns two distinct handles:

- `StartTraceW` returns the controller/session handle. It is stopped with
  `ControlTraceW(EVENT_TRACE_CONTROL_STOP)`.
- `OpenTraceW` returns the consumer/processing handle. It is closed with
  `CloseTrace`.

`ProcessTrace` runs on a dedicated worker because it blocks while dispatching
real-time records. The callback filters provider GUID and event ID, asks TDH for
the registered metadata, reads required properties by name, copies them into a
`RawProcessEvent`, and returns without retaining Windows-owned pointers.

Normal stop disables the provider, stops the session, closes the consumer, and
joins the worker. Partial startup failures unwind in reverse order. The fixed
session name rejects a second running Officer instance instead of silently
stealing its session.

## Sysmon lifecycle

The Sysmon collector creates a push subscription for future event ID 1 records.
Windows invokes its callback on Event Log service callback threads. Each event
is rendered to transient UTF-16 XML, converted to UTF-8, decoded, and copied
into `RawProcessEvent`.

Stopping closes the subscription and waits for callbacks already in progress
before destroying callback state.

## Field coverage

ETW provides PID, start time, parent PID, and image path. It does not provide
the command line or process-owner SID in this event.

Sysmon also provides command line, account name, configured hashes, parent
image, channel, and record ID. Optional facts remain null when a source does not
observe them.

Sysmon timestamps normally have millisecond precision while ETW `FILETIME`
values have finer precision. Entity identity therefore canonicalizes the common
start time to milliseconds. Event identity retains the full source timestamp
and provenance.

## Current callback boundary

Phase 2 intentionally uses a direct callback:

```text
collector -> RawEvent sink -> normalize -> serialize -> stdout
```

The callback is the future queue insertion seam. Console serialization is safe
for this process-only milestone, but it is not suitable for high-volume
telemetry because a slow sink can make a real-time consumer fall behind.

No queue is introduced in Phase 2 because it would add capacity, backpressure,
loss accounting, and shutdown policy to a milestone whose purpose is validating
live acquisition. Phase 3 can replace the callback body with a bounded queue
push without changing either collector.

## Why raw APIs instead of krabsetw

`microsoft/krabsetw` provides a friendlier C++ wrapper, reducing ETW boilerplate
and making common subscriptions concise. Raw APIs require more RAII and error
handling, but expose the exact Windows lifecycle, avoid another runtime-facing
dependency, and make session, callback, and TDH behavior explicit for this
teaching project. Officer therefore uses the raw APIs behind its own narrow
collector interface. A future adapter can change its internal library without
changing `TelemetryCollector` or `RawEventSink`.

## Build-system boundary

CMake adds one static target, `officer-collectors`, containing both adapters and
the testable Sysmon XML decoder. It has `include/` as its public include root,
links publicly to `officer-core`, and privately to:

- `advapi32` for ETW controller/consumer APIs and registry/runtime metadata.
- `tdh` for manifest-based ETW property decoding.
- `wevtapi` for the Windows Event Log subscription and rendering APIs.
- `tinyxml2` for the Sysmon XML decoder.

`officer-agent` links `officer-core`, `officer-collectors`, and `advapi32`.
The TinyXML2 DLL is copied beside executables that need the dynamically linked
vcpkg package. Keeping collectors in their own target prevents Windows
acquisition dependencies from leaking into the source-neutral core contracts.

## Privilege model

The development milestone is run from an elevated terminal. Controlling a
system ETW session is restricted, and the Sysmon Operational channel has an
access-control descriptor that may deny ordinary users. A production service
should receive only the ETW and Event Log rights it needs; “run as administrator”
is a development instruction, not the final least-privilege design. Officer
warns when its token is not elevated and reports each source's Windows error
independently, allowing one collector to run if the other is unavailable.

## Limitations

- Collection is process-start only.
- There is no queue, durable spool, delivery, bookmark persistence, or service.
- Sysmon begins with future events; it does not replay channel history.
- A hard process termination cannot execute RAII cleanup. A stale ETW session
  may require elevated `logman stop Panopticon-Officer-Process -ets`.
- Persistent agent enrollment identity is not implemented. Phase 2 derives a
  development identity from the Windows machine identity.

## Primary Windows references

- [About Event Tracing](https://learn.microsoft.com/windows/win32/etw/about-event-tracing)
- [`StartTrace`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-starttracew)
- [`EnableTraceEx2`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
- [`OpenTrace`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-opentracew)
- [`ProcessTrace`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-processtrace)
- [`CloseTrace`](https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-closetrace)
- [`EVENT_RECORD`](https://learn.microsoft.com/windows/win32/api/evntcons/ns-evntcons-event_record)
- [`TdhGetEventInformation`](https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation)
- [`TdhGetProperty`](https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhgetproperty)
- [`EvtSubscribe`](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtsubscribe)
- [`EvtRender`](https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtrender)
