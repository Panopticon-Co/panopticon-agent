# Process termination evidence

The ETW Kernel-Process worker accepts process start ID 1 and stop ID 2. Stop
decoding requires typed ProcessID/CreateTime/ExitTime properties from TDH,
nonzero creation ticks, a non-inverted native clock and a representable exit
time. ExitCode is retained if the native template exposes a UInt32 property.
The callback's writer/header PID is not used as subject identity. Metadata,
property copies, property-array extents and metadata name termination are bounded.
Other provider/version layouts remain subject to compatibility qualification.

The Sysmon subscription now includes ID 5 and the process decoder accepts IDs
1/5. A stop retains its GUID/PID/image/user and independent UtcTime. It does not
manufacture creation FILETIME from that formatted clock. Duplicate named data
fields are rejected as ambiguous. Termination never overwrites the process-start
image cache or enters the legacy process-start normalizer. See
[Microsoft Sysmon events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

The dedicated canonical `process_stop` observation preserves source facts,
termination clock/native ticks/exit code and an exact native or source-scoped
process reference. Missing tokens/GUIDs leave identity null. Native and Sysmon
identities are not joined by PID or timestamp proximity. A stop does not invent
birth evidence or ancestry. The event is durably accepted before the resident
store is tombstoned. A duplicate later stop cannot move an earlier tombstone,
and an old instance stop cannot terminate a reused PID's different entity.
Canonical serialization failures retain decoded failure evidence when admitted.

This is still a bounded resident cache, not the complete durable host process
graph. A stop record is durable evidence even if resident admission fails.
Unavailable sources produce blind scoped stop health; an active source produces
degraded health until configuration/continuity/live lifecycle are qualified.
Native decode failures still require full original-byte evidence/loss closure.

## Evidence and remaining work

`officer-process-lifecycle-tests` builds a synthetic event ID 2 version 0 payload
from the actual host's TDH metadata, including its ANSI image field. It exercises
the real TDH parser, native creation/exit clocks, truncated payload refusal,
Sysmon stop XML, duplicate GUID refusal, PID reuse, late duplicate tombstones,
source/native identity separation and refusal to normalize a stop as a birth.
This is native API component/ABI evidence, not a live kernel notification.

Three fixtures pass endpoint Schema 1.0 and Manager native-data preservation:
`demo-run/process-lifecycle/1d342c71e5914394ac80e2bba006b051/report.json`.
Subsequent dedicated guest validation retains nine live privileged ETW births
and nine stops. The owned ping target's PID/creation FILETIME and native exit code
match exactly one stop in both delivery and immutable archive after abrupt exit;
the durable graph returns its birth and stop with null liveness. See [validation](VALIDATION.md).
Configured Sysmon ID 5 validation remains unverified. Full ancestry/creator-versus-requested-parent,
missed starts/stops, source policy/continuity, process churn, replay/reboot,
complete durable graph reconciliation, resource bounds and OS/version qualification remain
open. B remains partial; this increment does not close the lifecycle or tree DoD.
