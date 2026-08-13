# EyeTrace Query architecture

EyeTrace is a historical telemetry reader. It does not subscribe to live events,
run as a service, or make detection decisions.

```text
Sysmon Operational channel
  -> EventLogReader (EvtQuery, EvtNext, EvtRender)
  -> raw event XML
  -> SysmonParser (TinyXML2)
  -> TelemetryEvent
  -> NDJSON serializer
  -> stdout and optional output file
```

`EventLogReader` owns Windows Event Log handles through `WinEventHandle`. The
parser has no Windows API dependency, so it can be unit-tested with sanitized
XML fixtures. `TelemetryEvent` is the stable boundary that a future live
collector can also produce.

Supported historical Sysmon event IDs are 1 (process create), 3 (network
connection), 11 (file create), and 12-14 (registry changes). Sysmon must be
configured to record the event type before EyeTrace can query it.
