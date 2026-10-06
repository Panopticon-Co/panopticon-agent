# Native host state

An independent worker now also captures [native process state](PROCESS_STATE.md).
It preserves Toolhelp descriptors separately from later held-object identity/
image queries, maintains its own stable pending record and exposes record-bound
health. Host inventory does not absorb process descriptors into guessed actors
or parent instances.

System advanced audit policy is now queried with
[AuditEnumerateSubCategories](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditenumeratesubcategories)
and [AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy).
The latter requires appropriate audit-object access or SeSecurityPrivilege;
collection does not change policy, enable privileges or invoke auditpol. A failure
retains the exact Win32 error, query stage and enumerated count, with a null
policy value. On this non-elevated host, enumeration returns 60 subcategories
but the policy query fails with 1314; the endpoint reports unavailable, never
disabled auditing.

Successful collection retains native category/subcategory GUIDs and exact decimal
32-bit masks. The [documented flags](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information)
select success, failure or none. Raw bits are retained independently of derived
settings; zero, contradictory NONE-plus-selection and unknown masks leave derived
settings null/degraded. A healthy query can report NONE; this means an observed
query result, not a healthy security configuration. Native allocation ownership
uses AuditFree, with count capped at 256 and requested/returned identity uniqueness
checked before claiming complete enumeration. The snapshot remains non-atomic.
It does not inventory per-user/effective-token policy, audit options, log delivery,
SACLs, policy origin or change continuity. API deadlines, elevated/service-account
success, failure/malformed-buffer and OS matrix qualification remain open. Scoped
`state.system_audit_policy` coverage and query metadata are bound to the last
durably committed snapshot.

The actual console runtime now captures `kind=state`, `category=host_inventory`,
domain `host_state_version=1.0` after attempting event subscriptions, then every
five minutes after a successful durable commit. A separate inventory worker runs
queries outside event callbacks and the source supervisor. It retains one pending
serialized snapshot, with the same record identity, until the journal accepts it.
Pending state is bounded but not crash-durable until acceptance. The worker stops
before transport shuts down. Query APIs remain synchronous; allocation/retry bounds
do not establish query or shutdown deadlines. Worker isolation/timeouts, signed
refresh policy and failure qualification remain required.

The agent now continues host state and health when no event collector subscribes.
Selected sources remain unavailable; expected process visibility is blind. This
does not imply an event-source fallback exists. The absent-event condition no
longer prevents reporting independent host inventory.

Each snapshot explicitly says `inventory_complete=false`,
`snapshot_type=full_for_implemented_fields`, and `consistency=non_atomic`. Uptime
start/end values bound the collection window. They do not establish that all
facts were true at one instant or that configuration changes between polls were
observed. The canonical stream's installation/generation/epoch/sequence orders
snapshots; source freshness remains unverified. Collection after subscription
does not establish host-change event continuity: corresponding watchers are not
implemented yet.

The 24 current fields cover physical hostname/FQDN; native OS major/minor/build,
service pack, suite/product type; registry product/edition/display version/UBR;
native and agent machine types; physical memory; firmware type; registry
manufacturer/model/BIOS vendor/version/date; domain/workgroup join report; network
adapters; the Windows registry Secure Boot report; logical processors across
processor groups; uptime; native TPM compatible-device/version facts; and scoped
default Entra join information; and native local volume inventory. Virtualization
remains an explicit unavailable/null field with a not-implemented reason.

Storage now enumerates local Windows volume GUID paths with FindFirstVolumeW and
FindNextVolumeW, retaining names independently of successful child queries. Each
volume carries separate mount-path, filesystem/label/format serial/flags, quota-aware
space and drive-type query state. Mount paths include drive letters and mounted
folders; a successful empty list differs from failure. MULTISZ parsing uses the
returned bounded count, validates the final terminator, rejects trailing data and
never reads through a missing terminator. Native labels/path text uses existing
lossless invalid-UTF-16 handling. Native volume search handles close through RAII.
Critical-error dialogs are suppressed only on the query thread; its prior error mode
is restored on all scope exits. API calls remain synchronous, without qualified deadlines.

Volume enumeration retains at most 128 volumes/256 KiB of encoded volume-array
payload. Mount-path growth allows four attempts/65536 UTF-16 units and 256 paths
per volume. Bounds/failure explicitly mark incomplete enumeration or unknown child
facts, retaining the known volume subset. The aggregate host record still requires
shared payload/resource-budget qualification. No remaining-volume count is guessed.
Enumeration errors and retained child-query failures are separate, with explicit
counter scope and limits. `GetDiskFreeSpaceExW` values use exact uint64 decimal
strings: caller-available free bytes, caller-available total bytes and volume free
bytes are distinct. Account quotas can affect the first two; none is physical disk
length, an allocated emergency reserve or an enforced spool budget. Filesystem flags
are reported capabilities, not a BitLocker/encryption-state claim. Format serial
numbers and volume GUID paths are not verified persistent physical-device identity.

Storage remains degraded even when all scoped volume queries succeed. Physical
disk/extents/topology, hardware serials, removable-device inventory, encryption,
network shares, storage changes/deltas and reconciliation remain incomplete. The
current development host exposes four local volumes with complete name enumeration
and successful child queries; that is one-host evidence, not storage qualification.

TPM query uses Tbsi_GetDeviceInfo through a System32-only dynamically loaded TBS
module, without a TPM command context, ownership/authentication material or platform
changes. It preserves TBS_RESULT separately from Win32/HRESULT errors, version and
structure numbers, and uninterpreted reserved interface/revision fields. Only the
documented TPM-not-found status becomes `compatible_device_found=false`; service
and other query failures stay unknown. Unknown versions are degraded with raw
values. Device/version facts do not establish readiness, enabled/owned state,
PCRs, key protection or attestation. Reserved values are not interpreted as a
security or hardware capability. The live host reports TPM 2.0 and structure version 1.

Entra query uses NetGetAadJoinInformation with no tenant filter. It reports the
device join or one default work account of the collector's current user, with
raw join type, device/tenant/domain/display-name/join-email and MDM endpoint metadata.
MDM URLs are configuration metadata, not enrollment/compliance proof. Join certificate
and user-information presence flags disclose no certificate/private-key/authentication
material. All-user/all-tenant inventory explicitly remains incomplete; multiple
work-account selection is unspecified by Windows. Missing native exports are
unsupported; module/query failures preserve their own error domain and unknown value.
The matching native release function and module are RAII-owned even on serialization
exceptions. Each returned string is limited to 4096 UTF-16 code units; bound-exceeded
fields are null, named explicitly, and the result degraded. Null, empty and invalid
UTF-16 retain their existing distinct representations.

S_OK with null join information means scoped absence. Informational success codes,
including the live host's S_FALSE, are not HRESULT failures: the raw status and
returned information remain, the result is degraded and `join_kind=unknown` until
that interpretation is qualified. Failing HRESULTs preserve unavailable/null state.
Unknown join types retain their raw values without claiming unjoined or unsupported.

Fields carry the six-state vocabulary, source, reason, and nullable error code.
`healthy` means only that the named field query succeeded on this sample. The
overall host capability stays degraded. Unknown values never become false or
empty collections. Registry queries additionally preserve HKLM path/value name
and 64-bit view. Registry labels, revision and Secure Boot values remain reports;
they are not hardware/boot attestation or inferred product names. Native OS build
is distinct from registry marketing labels. Architecture uses IsWow64Process2;
it is not guessed from process emulation or GetNativeSystemInfo.

Adapter scope is the current network compartment, all requested interfaces,
IPv4/IPv6 unicast and DNS addresses. It retains interface/LUID indices, type,
status, flags, MTU, MAC, link speeds and IPv6 scope IDs. It does not constitute
socket/flow attribution, routes, VPN state or all-compartment inventory. Queries
start with 15 KiB and allow at most four growth attempts/4 MiB; at most 512
adapters and 4096 addresses are represented. Bounds or conversion/truncation
make the group degraded and retain null/unknown facts. Exact byte/speed/uptime
uint64 values use decimal strings. Invalid UTF-16 text is retained as explicit
UTF-16LE hex, rather than silently repaired.

Health exposes committed count, collection progress/start time, pending durable
acceptance, commit failures and last committed uptime. These describe the worker,
not current coverage of every host-security domain. Process restart resets these
runtime counters. Snapshot records remain encrypted in the journal and immutable
in Manager; `/latest` uses existing generation/sequence projection rules. Detection
receives `endpoint_state_host_inventory` and the complete domain payload without
creating a process actor. Console and full domain state rules remain unfinished.

Health now includes per-field query state/source/reason/error domain/status bound
to `last_committed_record_id`. Scoped `state.tpm_device` and
`state.entra_default_join` and `state.storage_volumes` capabilities match the last committed snapshot. Their
coverage updates and host-health projection share a lock during publication; the
overall health record remains non-atomic across independent components. The W/Y
domains stay degraded when scoped identity/posture facts are available and retain
explicit full-domain limitations. These are sampled query facts, not live change
continuity, attestation, current-user enumeration or a service-account qualification.

Validation includes real read-only queries on this x64 host, field uncertainty,
exact canonical JSON, Manager/schema/projection/Detection adaptation, and the
actual non-elevated agent remaining active with ETW unavailable. An isolated test
terminates only its owned Popen process and reopens its own spool to verify exact
committed snapshot and health recovery. Run Manager's Python environment with
`tools/verify_host_inventory_runtime.py`. It does not enroll, elevate, change
provider configuration, install certificates, upload to a real backend or touch
another agent's files. One current query sample measured 78 ms; that is not a
CPU/RSS/latency budget or compatibility qualification.

Remaining major work includes TPM/Secure Boot attestation, complete Entra identity,
physical disks/extents/removable storage and full volume/encryption state, CPU/hardware detail, virtualization,
identity clone/replacement lifecycle, versioned deltas and event reconciliation,
users/sessions/services/tasks/persistence/security-posture state, API fault
injection/timeouts, reboot/privilege/version/ARM64/Server/Core compatibility,
performance/soak and fleet investigation/response integration. No complete host
inventory or full Windows endpoint claim.

Primary API references:

- [RtlGetVersion](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion)
- [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2)
- [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
- [NetGetJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetjoininformation)
- [GetFirmwareType](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype)
- [Tbsi_GetDeviceInfo](https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo)
- [TPM_DEVICE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info)
- [NetGetAadJoinInformation](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation)
- [DSREG_JOIN_INFO](https://learn.microsoft.com/en-us/windows/win32/api/lmjoin/ns-lmjoin-dsreg_join_info)
- [HRESULT success and failure](https://learn.microsoft.com/en-us/windows/win32/learnwin32/error-handling-in-com)
- [FindFirstVolumeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew)
- [GetVolumePathNamesForVolumeNameW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew)
- [GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw)
- [GetDiskFreeSpaceExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw)
- [SetThreadErrorMode](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setthreaderrormode)
