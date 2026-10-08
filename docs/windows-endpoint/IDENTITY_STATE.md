# Native account, group and session state

Four independent Windows workers capture local accounts (NetUserEnum level 20
and later NetUserGetInfo level 23), local groups/direct members
(NetLocalGroupEnum and NetLocalGroupGetMembers), LSA logon descriptors/data,
and local WTS sessions/selected client fields. They do not mutate accounts,
groups or sessions and do not retrieve passwords or authentication secrets.

Each capture has a durable begin, bounded ordered pages and a manifest naming
the accepted page record IDs. A refused journal admission retains the same
bytes/record identity; native enumeration does not advance past that pending
page. Health exposes query and copy refusals, cancellation, soft budget limits,
enumeration completion and record-bound monotonic freshness. Enumeration
completion describes this API traversal, not complete Windows identity coverage.

Copies validate returned buffer extents, UTF-16 termination/counts and SID
boundaries where the native API supplies an allocation extent. LSA nested
pointers rely on its documented allocation contract; bounded field copies do
not establish an independently known allocation extent. Native calls and native
allocations are not subject to a guaranteed hard deadline or memory bound.

Accounts and groups are queried against the local server. Later name-based
account/member lookups are not atomic with enumeration; association stays
unverified. Direct membership does not prove effective/transitive access.
LSA LUIDs and WTS session IDs remain raw native identifiers: neither is promoted
to a canonical process/logon entity or a durable session lifetime. WTS client
address bytes and address family are retained without guessing an IP address.
No process actor is inferred from an inventory getter.

## Evidence and remaining qualification

2026-10-07: fresh MSVC x64 Debug and Release builds pass all 34 CTest entries
(23.67 and 23.32 seconds). Boundary fixtures exercise malformed and unterminated
text, counted strings, SID extents, unsupported WTS fields and consumer refusal.
Real host queries retain seven account rows, 50 group/member/summary rows,
26 logon rows and two WTS rows. Of the 26 logon queries, 24 return NTSTATUS
3221225506 (0xC0000022, access denied); two return data. The denied rows remain
explicit. No complete logon census is claimed.

Owned 20-second Debug/Release agent runs, followed by abrupt termination and
stopped-spool recovery, retain 4,238/13,200 records. All seven identity and
persistence capture sets assemble and their accepted manifests match committed
health. Both complete readbacks are byte-identical; all runtime records plus
88 component fixtures per build validate against endpoint Schema 1.0 and
preserve their native data through the Manager EndpointRecord model.

Evidence: `demo-run/identity/persistence-runtime-263852cfe0ac46899062d94bd51ed990/report.json`
and `demo-run/identity-release/persistence-runtime-951f0afa1feb4ba595720ebccac88cce/report.json`.
These are development-host runtime checks, not VM, fleet, soak or privilege
qualification. The guest validation package includes all four sources but has
not run inside the dedicated Windows VM.

Still required: privileged/standard-user and OS/configuration matrices,
domain/Entra identity, effective privileges and impersonation, atomic lifetime
correlation, change watchers/reconciliation, concurrent account/session churn,
RDP/WinRM/SMB authentication and remote execution attribution, hard native-call
isolation, resource/chaos/reboot qualification and supported service deployment.
Capabilities D and U remain partial.
