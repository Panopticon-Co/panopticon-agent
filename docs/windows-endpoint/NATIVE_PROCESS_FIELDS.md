# Native ETW process scalar evidence

The Kernel-Process adapter retains nineteen selected UInt32/UInt64 properties
from actual TDH metadata and payload reads. They include process/parent sequence
numbers, session, raw token/flag/mitigation/checksum fields and stop handle,
commit, CPU, I/O and hard-fault counters. Names follow the source template;
numeric values are not translated into policy, protection or resource-unit claims.

`source_facts.process.native_fields` uses `windows_etw_process_fields_v1` and
retains provider GUID, event ID/version, per-field native in-type, TDH status,
reported byte count and a lossless decimal string. A missing property is
unsupported **in that template**, not evidence that the whole platform lacks
the capability. Type/array ambiguity, unexpected sizes and failed reads are
unavailable with null values. A failed optional read does not invent a value.
Mandatory process identity/clock decoding retains its existing refusal behavior.

Fixed arrays keep the supplemental payload bounded; scalar reads use an
eight-byte stack carrier. Metadata still uses the existing 2 MiB application
copy bound, with no hard bound on TDH internal allocation or deadlines. The raw
handoff's `sizeof(RawEvent)` charge and fixed-ring measurement include the larger
inline payload. Storm/CPU/memory/latency qualification remains open. Full native
payload bytes, SID/package strings and all possible version fields are not
retained by this selection.

Process sequences are source facts, not GUIDs or creation FILETIME. Current
canonical entity IDs remain boot/PID/creation-token or independently scoped
source GUID identities. This wave performs no sequence alias promotion or parent
instance resolution. Resolving those relationships still requires qualified
boot/source scope, exact coassertion and conflict evidence, bounded persistent
alias indexing, older-template fallback and live parent validation.

The host manifest exposes birth versions 3/4 and stop version 2 with sequence
properties. Metadata evidence is recorded in [process graph](PROCESS_GRAPH.md).
Microsoft documents a unique process sequence in a newer
[SystemBasicProcessInformation API](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation),
available from build 26100.4770. That does not independently establish equality
between that API's sequence and the ETW properties; no such join is implemented.

## Validation

Fresh Debug/Release builds pass all 39 CTest entries (25.82/25.41 seconds).
Actual-host TDH template fixtures cover stop version 0, stop version 2 and birth
version 3, including UINT64_MAX process sequence, UINT64_MAX-1 parent sequence,
UINT32_MAX flags, precision-preserving normalization and older-template absence.
Truncated mandatory payloads are refused. Source-fact tests refuse wrong source,
operation and inconsistent copy/value evidence. Handoff tests retain supplemental
fields under capacity/in-flight pressure. These are component/synthetic payload
tests, not live notification evidence.

The guest harness checks nineteen selected fields on the owned exact native stop
and, when both templates provide it, requires its birth/stop process sequences
to agree. Live template versions, failure states and canonical envelope/body
preservation are checked by `tools/validate_native_process_fields.py` after export.
Current staged package: `staging/build-20261007-050754`. Live guest execution
passes all 21 selected component executables, then recovers 1,640 unchanged
Schema 1.0 records with Manager native-body preservation and package hashes.
Four lifecycle originals contain two real birth-version-4 records and two
stop-version-2 records. All four process sequences are copied; both births
retain parent sequences, raw token/flag/mitigation and image metadata. Both
stops retain all eleven applicable selected resource/token/sequence scalars.
The owned target's birth/stop sequence agrees, with its exact PID/creation
FILETIME/exit and retained graph independently checked. Absent fields remain
template-scoped unsupported, not fabricated zeros. Native/schema/body verification
passes for the live records and separate synthetic fixtures. Evidence:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\guest-native-process-fields-20261007/native-process-fields-report.json`
and `host-verification-report.json`. Parent instance resolution, alias authority,
full raw payload/field coverage and OS/resource/soak qualification remain open.
B/Y/AK remain partial; thread/handle interaction telemetry remains missing.
