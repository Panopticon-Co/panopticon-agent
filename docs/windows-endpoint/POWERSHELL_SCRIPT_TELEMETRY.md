# Windows PowerShell script telemetry capability

This capability layer is wired into the Windows Event Log channels
`Microsoft-Windows-PowerShell/Operational` and `Windows PowerShell`. Its source
is intentionally separate from `WindowsEventLog`: the native event reader
retains its existing raw XML and EventData, then adds a compact nested
PowerShell semantics object. Health also reports the read-only channel and
common registry policy observations. The source and decoder are part of the
Windows collectors build.

## Read-only coverage inspection

`inspect_powershell_logging_coverage()` queries each channel's native enabled
configuration and attempts to open the channel for reading. It also observes
the HKLM and HKCU values for script block logging, invocation logging, module
logging, and transcription under
`Software\Policies\Microsoft\Windows\PowerShell`. It performs no registry
writes and never calls the API that changes channel configuration.

The resulting `coverage_state` is intentionally qualified. A configured
enabled channel does not prove the provider is generating events, the relevant
audit policy is effective, or the process can retain every record. Registry
observations are not Resultant Set of Policy. The module allowlist and
transcription destination are not inspected. Classic channel availability and
event shapes vary across Windows versions. The caller should combine this
snapshot with the event collector's own subscription, retention, loss, and
durable-acceptance health.

## Event decoding and retained fields

`decode_powershell_event_xml(xml, requested_channel)` retains the complete
rendered XML, System event version and other System fields, provider identity,
event-writer PID/TID and SID claims, and each `EventData` element as both text
and XML. It labels common source event IDs: 4103 module logging, 4104 script
block logging, 4105 invocation start, 4106 invocation finish, and 400/403
engine lifecycle. The meaning is emitted only when the channel and provider
match the expected PowerShell source. These are source-native labels, not
detections.

Event `Execution/ProcessID` identifies the event writer metadata; it is not
proof of the process that executed the script. User fields in event data and
`System/Security` are retained as claims and do not establish a token, logon
session, or subject identity. Downstream correlation must preserve that
uncertainty.

Event 4104 is represented as a script-block fragment with its ScriptBlockId,
MessageNumber, and MessageTotal when those fields are present. The decoder
explicitly reports `assembled: false` and never joins fragments. Missing,
repeated, reordered, or dropped records therefore remain visible as
limitations. The raw fragment text remains in raw EventData; it can contain
sensitive script content and should be handled under the product's telemetry
retention and access policy.

## Integration boundary

The component is integrated into the Windows Event Log decoder and health
report. It does not add channels to the subscriber defaults, enable any channel,
or alter PowerShell policy. Component and live Windows evidence is pending; this
integration has not been built or tested in the current deferred-test wave.
