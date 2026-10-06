# Defender status capture

An independent five-minute worker reads the local
`Root\Microsoft\Windows\Defender:MSFT_MpComputerStatus` WMI class. It captures
the 32 documented base status properties and `__RELPATH`: engine/service/product
versions, eight reported protection switches, signature versions/ages/dates,
scan dates/ages/sources and direction, raw ComputerState and descriptive ComputerID.
Collector version 1.1 additionally selects three modern optional properties:
AMRunningMode, IsTamperProtected and TamperProtectionSource, for 36 total getters.
Their presence varies by installed provider; the legacy class minimum does not
establish modern-property availability. The current local CIM class reports
String, Boolean and String respectively.
No methods, scans, remediation or configuration writes are invoked. Fleet rules
and correlation remain in the Detection Engine.

Microsoft documents this class for Windows 8.1 and Server 2012 R2 onward; that
minimum is not a qualification claim for any Panopticon deployment. The source
is independent of client-only WSC. A namespace/class refusal retains its native
HRESULT as unavailable; it does not prove Defender is absent, disabled or healthy.
See [class contract](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus).

Modern status fields are shown in Microsoft's [Get-MpComputerStatus documentation](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2022-ps).
The [compatibility guidance](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
names Normal, Passive and EDR Block Mode. Only exact known strings from a canonical
successful query receive reported_mode; future/empty/altered strings retain raw
and typed text with null interpretation. A failed or unusual success HRESULT or
CIM mismatch cannot grant a trusted mode. Known Boolean tamper false/true yields
reported disabled/enabled while getter quality remains separate. Malformed/null
values remain unknown; TamperProtectionSource is descriptive text and never
establishes verified policy authority. Every property keeps protection_verified
false. WBEM_E_NOT_FOUND means not_exposed_by_object with unavailable value and
exact HRESULT; other refusals remain query_refused. Neither infers OS support,
provider absence, a running mode or disabled protection.

Each property retains query start/end uptime, exact HRESULT, reported CIM and
VARIANT types, raw scalar/text, typed value or null, separate validation status,
and VariantClear result. UTF conversion failures also preserve the exact Win32 error. A successful getter with reported false is known false,
not missing data; it is still a provider report, not verified effective protection.
The documented WMI mapping uses VT_I4 for uint32 and VT_UI1 for uint8; signed raw
bits and unsigned decimal interpretation remain separate. Age sentinel 65535 is
preserved. DATETIME strings retain provider representation without invented UTC.
See [numeric mapping](https://learn.microsoft.com/en-us/windows/win32/wmisdk/numbers).

The decoder refuses coercion, BYREF dereference, arrays, null and invalid Boolean
representations. Exact BSTR lengths preserve embedded NUL; malformed UTF-16 or
odd-byte strings retain bounded raw hex. Text copying is limited to 8 KiB per
property and 32 KiB per object. At most eight rows and 640 KiB encoded entries
are retained; a ninth object or encoded refusal is explicit, not a native event
loss count. Trusted native/provider allocations, JSON memory and aggregate RSS
are not covered by those copy/encoded bounds. Product/process/device references
remain null; ComputerID and object paths do not establish verified lifetimes.

The worker owns its MTA initialization and balances successful S_OK/S_FALSE calls.
An incompatible existing apartment retains RPC_E_CHANGED_MODE without changing
the caller's apartment. COM references and variants are released before journal
acceptance. Local connection uses caller context; no process-wide COM security
initialization or privilege changes occur. Both service and enumerator proxies
use packet privacy and impersonation with explicit HRESULT evidence.

Enumeration requests one object with a one-second Next timeout; a returned final
object is processed before closing a WBEM_S_FALSE enumeration. Timeout retains
the already captured prefix without asserting completion. ConnectServer uses
the documented maximum-wait flag (up to two minutes). ExecQuery/property getters
and the entire collection have no independently enforced deadline. A stuck
collector can still impede graceful worker join; source isolation/cancellation
qualification remains required. See [Next](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next)
and [ConnectServer](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver).

`defender_status` is a canonical state record. Journal retry preserves its record
ID and body; diagnostic output follows acceptance. Health binds the exact query
status and capture-start/commit clocks to that record. `state.defender_status`
describes this partial source. Three state.defender_status.<property> capabilities
expose retained-row query/interpretation quality and follow capture freshness.
Their quality summary excludes undelivered rows; missing fields and refusals
prevent a fully healthy quality summary. No captured rows means unavailable
property evidence, even if the provider completed an empty enumeration. Capture freshness and durable sampled transition
history apply independently. Q.security_product remains degraded when either
fresh source supplies partial evidence; one provider's refusal or unsupported
contract cannot erase the other's fresh report. Both sources' freshness remains
observable. No combination establishes full product coverage or protection.

Current evidence: native tests cover numeric/Boolean uncertainty, CIM mismatch,
sentinels, null/BYREF/array refusal, counted/malformed text, copy bounds and COM
apartment ownership. Manager tests preserve native and decoder/refusal records
through published schema, authenticated duplicate ingestion, immutable readback
and unchanged Detection data without guessed actor identity. Owned runtime and
unread-output runs retain this eleventh state source and record-bound health
through journal reopen. Native failure/boundary injection, blocked providers,
service accounts, Server Desktop/Core, ARM64, reboot/suspend, load and soak remain
unqualified. Effective passive/tamper enforcement and ASR/exclusion/preferences policy, other products,
signers, notifications and reconciliation remain gaps. Inventory_complete and
protection_verified remain false; no domain is complete.
