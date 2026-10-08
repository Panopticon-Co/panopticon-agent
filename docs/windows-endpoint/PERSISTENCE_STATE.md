# Native persistence state

Three independent Windows workers capture scheduled tasks, permanent WMI
subscriptions and selected startup mechanisms. Each emits common/versioned
endpoint records with a durable begin, indexed bounded pages and an ordered
manifest referencing the accepted page IDs. They run without Detection or Sysmon.
Immutable canonical bytes retry until journal acceptance; the native iterator
does not advance during refusal. Interrupted begin/page sets remain incomplete.
Pending application memory is not crash-durable before acceptance.

The five-minute capture interval and six-minute maximum capture age bind health
to the accepted manifest. Overdue inventory becomes blind; a separate eligible
native source can still provide explicit partial domain evidence. Stopped new
workers report disabled. A complete retained page assembly proves neither
continuous change coverage nor a complete native/domain census.

## Native scope

Task Scheduler uses local COM, one-based indices, TASK_ENUM_HIDDEN and
GetFolders(0). Bounded full definition XML, ordered duplicate/unknown sections,
name/path, raw state, enabled Boolean, last-result/missed-run reports and selected
owner/group/DACL SDDL are retained. OLE DATE bits and finite values remain raw;
UTC and sentinel interpretation are unverified. Configured actions, triggers and
principals are not observed execution or effective authorization. Malformed or
unknown-namespace XML refuses structural interpretation while retaining bounded
original XML. A held proxy does not prove immutable task/file/process identity.
Service-hidden inaccessible objects can remain silently omitted.

WMI queries local ROOT\subscription and ROOT\cimv2 independently for __EventFilter,
__EventConsumer subclasses and __FilterToConsumerBinding. Bounded MOF retains
unknown/third-party consumer configuration. Selected fields preserve exact native
VARIANT/CIM types, null/empty, Boolean false/true, integer strings, malformed text,
CreatorSID bytes and unresolved Filter/Consumer references. Neither references
nor consumers are activated. CreatorSID is reported security data, not an
authenticated actor/process. Other namespaces/providers remain unobserved.
Next(1000,1) retains returned objects before WBEM_S_FALSE; timeout is not EOF.

Startup queries Run/RunOnce/Policies Explorer Run in HKLM, collector HKCU and
loaded HKU SID hives, explicitly across 32/64 views. Allowlisted Winlogon
Shell/Userinit/AppSetup/TaskMan and AppInit fields retain configuration; unrelated
Winlogon secrets such as DefaultPassword are not queried. Exact bounded registry
type/bytes survive invalid/unterminated UTF-16 and scalar refusal; expandable text
is never expanded or executed. ERROR_MORE_DATA output is never decoded.
Current-caller/common Startup folders retain directory metadata and reported
reparse tags without recursion or shortcut resolution. File/target lifetime,
contents/signers and execution remain unverified. Unloaded users, other user
Startup folders, Active Setup, StartupApproved, COM/IFEO and other mechanisms
remain future work.

## Bounds, evidence and remaining gates

Defaults: 64 rows/page, 512 KiB encoded page, 16,384 entries, 1,024 pages,
128 KiB selected field copy, and a 60-second budget checked between native calls.
Task-folder and loaded-HKU index traversal also have separate 1,024 bounds.
Copy/row refusal, query failures, consumer refusal, cancellation and bounds are
observable. COM/RPC native allocations and calls have no hard memory/time bounds.
Isolation/deadlines, privacy/redaction controls, state deltas/reconciliation,
remediation, native fault/OS/privilege/resource/soak and analyst assembly remain
incomplete. These are partial capabilities, not full domain qualification.

Fresh MSVC x64 Debug/Release builds pass all 33 CTest entries. Native host checks
retain 371 task/folder, nine WMI object/scan and 92 startup rows. Four Run-key
access refusals affect loaded LocalService/NetworkService across both views,
preventing complete startup enumeration. A 20-second owned Debug runtime recovers
5,851 records after abrupt termination. All three manifest/page sets assemble
exactly, accepted health references their manifests, and second WAL readback is
identical. All 37 native component and 5,851 runtime records pass Schema 1.0 and
Manager body preservation. This is host functional evidence, not VM/fleet/soak
qualification. Evidence:
`demo-run/persistence/persistence-runtime-7b5ab233966c4bbea86b45b74dd60f44/report.json`.

The separate Release 20-second run retained 10,071 records. Its original harness
hit the explicit 10,000 aggregate read bound; a new bounded-page streaming mode
verified the same stopped spool completely without rerunning the endpoint. All
10,071 originals pass Schema/Manager preservation, and complete second readback
has identical SHA-256. Evidence:
`demo-run/persistence-release/persistence-runtime-57dfe38ec14e4abcb824cd9f48a19987/report.json`.

Guest scripts include this wave plus optional dedicated-guest fixtures: a hidden
disabled task and inert Run value. Prepared fixtures are not guest test evidence.
See [VM workflow](WINDOWS_VM.md).
