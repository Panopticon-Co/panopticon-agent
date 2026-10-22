# ETW process session ownership

The process collector allocates a unique native session name and GUID for each start. Before StartTrace, it durably commits a versioned ownership intent and a canonical gap record to the same encrypted journal used by telemetry. The checkpoint binds installation scope, native boot, exact name/GUID, owner PID and native process creation FILETIME. Missing durable callbacks or refused commit prevents startup.

On restart, only the exact session saved in that installation's authenticated checkpoint is eligible for reclamation. The collector queries the native GUID, requires matching boot identity, and verifies the original process has exited or its PID has been reused. Access denial or uncertain identity refuses reclamation. A final native GUID query precedes STOP. Normal shutdown also verifies its session GUID before mutation. No session enumeration, shared-prefix cleanup or blind stop is used.

This addresses a real guest failure: abrupt termination left the historical fixed-name session alive, and a subsequent run could not subscribe to process ETW. The old fixed-name session is deliberately not reclaimed automatically because the new ownership proof does not cover it. Unique sessions allow independent progress within native session capacity.

Limits: this is implemented and the main executable compiles; runtime recovery is unverified. A different/lost spool cannot reclaim the prior ownership checkpoint. Administrative replacement between query and STOP is not atomically fenced. Native privileges, system logger capacity, repeated crash/restart, lost journal, live competing owner, PID reuse and reboot require consolidated Windows validation. Unknown intervals remain gaps; session recovery cannot reconstruct lost events. No Windows ETW session limits are changed.

Native API references: [StartTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracea) and [system trace provider session configuration](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session).
