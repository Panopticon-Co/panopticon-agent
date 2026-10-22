# Typed Security authentication fields

The native Security-channel decoder now attaches `data.authentication` with
format `windows_authentication_v1` for exact Security-Auditing provider events
4624/4625/4634/4648/4672/4768/4769/4776. Existing rendered XML, ordered EventData,
bookmarks and journal transactions remain authoritative. Supported versions are
4624 v0/1/2, 4768/4769 v0/2, and v0 for the other selected events. Unknown versions
retain raw evidence and explicitly refuse typed interpretation.

Fields include separate subject/target account claims and full-width decimal
LUIDs, logon type, source address/port/workstation, package, elevated-token
resource value, status/substatus, reported requester PID/path and source outcome.
Missing, placeholder, duplicate, invalid/overflow and unsupported values retain
nulls with fixed reasons. Zero differs from missing. Duplicate EventData containers
refuse typed interpretation. Writer PID from System/Execution is never an actor.

A failed logon does not establish a target session. Explicit-credential use does
not imply successful authentication. Privilege assignment refers to the subject
logon; Kerberos/credential-validation outcomes describe their native operation,
not a new local logon. Event 4768's `TargetSid` is distinct from `TargetUserSid`.

These are reported source facts, not verified process or logon-session entities.
Retained events can predate the collection boot. The decoder leaves event boot,
process instance and session entity null rather than joining an old LUID/PID to
the current boot. Independently verified event-boot scope, durable session
lifecycle/process links and domain-controller/OS qualification remain open.

The test executable also accepts `<native-XML-file> <new-canonical-output-file>`.
`tools/validation/run_authentication_capture.ps1` uses normal UAC, reads at most
128 retained native records, selects one per available family, decodes through
the production factory and independently checks source identity/LUIDs/unknown
attribution. It does not generate logons, change auditing or loosen channel ACLs.
This is native retained-event evidence, not real-time subscription qualification.
See [validation](VALIDATION.md) for actual results.

Field meanings follow Microsoft's primary event references:
[4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624),
[4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648),
[4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768),
[4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769),
[4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776).
