# Windows endpoint engineering handoff

Updated: 2026-10-22

## Telemetry-context continuation checkpoint

Branch `codex/windows-telemetry`, [PR 5](https://github.com/Panopticon-Co/panopticon-agent/pull/5):
source candidate `5501139` repairs native build failures and false Event Log bookmark
resets from sparse record IDs; adds nine source-spelled EID1 context fields through
canonical source facts, bounded queue accounting and encrypted-journal recovery.
Fresh native Windows x64 Debug and Release builds pass 44/44 tests each; both initial
GitHub CI jobs pass. A repeatable elevated live Sysmon probe also passes, comparing
all nine new fields with native EID1 XML and verifying exact journal recovery.
See [validation](VALIDATION.md) and
[feature parity](FEATURE_FIELD_PARITY.md) for scoped evidence and consumer work.

Unelevated Sysmon access is denied on this host. Normal UAC elevation allowed the
live probe without changing channel permissions. The synthetic fixture remains
explicitly separate from real captured evidence. No dedicated-VM, Manager acceptance
or model parity is claimed. The existing lab-service-ledger branch and
running agent were preserved. Remaining work includes exact ETW/Sysmon alias binding,
canonical EID8/10/22, durable 4104 attribution, USN rediscovery, RDP/WinRM and the rest
of the approved plan. Later source-only/runtime claims below remain historical;
the latest validation entry supersedes only their build/component-test status for
this named candidate, not full capability qualification.

This handoff is for the next engineer continuing the Windows endpoint mission. The approved source plan is preserved verbatim in [FULL_SURFACE_ENGINEERING_PLAN.md](FULL_SURFACE_ENGINEERING_PLAN.md). The implementation remains incomplete; this handoff does not change the plan's A–AN scope or Definition of Done.

## Read these first

1. [Full Surface Engineering Plan](FULL_SURFACE_ENGINEERING_PLAN.md) — approved requirements, A–AN capability matrix and completion criteria.
2. [Capability matrix](CAPABILITY_MATRIX.md) — living implementation/gap ledger. Its current header says no domain is qualified complete; its current update is 2026-10-22.
3. [Validation ledger](VALIDATION.md) — evidence ledger. It contains later entries, including a 2026-10-09 native memory-region component wave. Reconcile this later evidence into the matrix as work proceeds; do not assume the matrix header is current.
4. [Windows VM workflow](WINDOWS_VM.md) — owned guest, installation, evidence, snapshots and validation procedures. Verify actual VM state before use.

The authoritative Windows endpoint repository is `panopticon-agent` inside the top-level Panopticon workspace. The implementation baseline before this documentation handoff is `d6afc2ff1bc1c98b6be50fc08d454699a3e924ed` (`feat: expand native Windows endpoint coverage`). That was the original documentation-only handoff; subsequent implementation waves are recorded below.

## Direction and boundaries

- Make the Windows agent an excellent standalone sensor and enforcement endpoint. Use Windows-native semantics and sources such as ETW, Windows Event Log, USN, SCM and Windows APIs; retain OS-specific event bodies inside a coherent versioned common envelope.
- Preserve common identity, sequencing, provenance, process-instance, health/loss, command and result semantics. Do not force Linux event structures onto Windows.
- Sokhi is rebuilding the Detection Engine. Keep endpoint work decoupled from its current implementation; validate endpoint contracts without spending effort on broad integration scenarios.
- Keep low-latency/offline local prevention bounded to the EDR role. Fleet-wide detection and correlation belong in the Detection Engine; do not expand this into an antivirus product.
- Kernel signing, HLK, PPL and ELAM qualification are eventual gates for capabilities that require them. They must not stall user-mode endpoint progress. Report degraded, unavailable, disabled, unsupported and blind coverage accurately.
- Protect Claude's concurrent Linux work. Never reset, clean, revert, overwrite or stop another agent's work or VM. The user authorized concurrent Windows/Linux VM use with the Windows guest at 4 vCPU and 4 GiB; check the live state and the workflow before operating the guest, and do not change the Linux VM.

## Evidence and current completion boundary

The matrix and validation ledger document substantial native implementation, component tests, and selected successful guest runs across process, filesystem/USN, service, state, log and response-related areas. The validation ledger records fresh Debug and Release suites with 42 tests for the 2026-10-09 memory-region wave. That wave verifies bounded `VirtualQueryEx` metadata at the native component level; it does not read process contents or prove injection, and the ledger explicitly does not treat it as dedicated-guest endpoint-runtime qualification.

Use each ledger entry to distinguish implementation, component evidence, real-Windows guest evidence, and remaining qualification. Historical guest runs establish only their named scenarios. They do not establish full source coverage, all-OS compatibility, soak/chaos behavior, protected-target behavior, or completion of A–AN. The matrix's Definition of Done remains unmet; do not promote a capability based only on compilation, test counts or a successful demo.

## Continuation sequence

1. Read the plan's full Definition of Done, then compare every A–AN row with current code and the dated validation evidence. Update the living matrix where newer evidence is missing or a status is too broad.
2. Choose the next substantial capability wave from the plan, prioritizing foundational process-instance identity, provenance, durability/replay, loss accounting, host state, safe response target verification, and endpoint health/coverage while maintaining breadth across the remaining surface.
3. Implement a coherent end-to-end slice in the Windows agent, with fault/restart/idempotency behavior and meaningful tests. Preserve explicit unsupported and unverified states rather than fabricating coverage.
4. Run consolidated real-Windows validation through the owned-VM workflow when feasible. Record the exact guest/build, scenario, evidence location and hash, failures, and what the run does not prove. Never label component-only results as guest or E2E validation.
5. Update `CAPABILITY_MATRIX.md` and `VALIDATION.md` in the same engineering wave, then continue to the next major gap. Revisit contract or other-repository changes only when a concrete endpoint requirement needs them; do not weaken endpoint capability to fit the current Detection Engine.

For any change that needs privileged kernel components, document the qualification dependency and continue independent user-mode work. Completion requires evidence across the plan's complete capability surface and explicit satisfaction of its Definition of Done, not merely a working VM or green test suite.

## Continuation update � 2026-10-22

Added [native module inventory](MODULE_INVENTORY.md), canonical paged runtime
integration and independent stale-capture health. Fixed the native category
selector so trailing thread/memory/module slots dispatch independently. Recheck
these three workers in the next consolidated guest run: the prior selector
aliased thread and memory despite older component/guest evidence. See the newest
validation entry for exact checks performed. No VM was started or changed in
this wave. Windows guest runtime, source completeness, protected targets, native
faults, recovery and performance qualification remain open.

## Extended registry persistence continuation � 2026-10-22

Added four independent native registry mechanism workers: Active Setup,
image-execution hooks (IFEO/filter/SilentProcessExit/boot/AppCert), COM
CLSID/AppID activation configuration, and raw StartupApproved state. See
[registry persistence](REGISTRY_PERSISTENCE.md). Native worker counts now derive
from their source arrays to avoid future hard-coded category/count mismatch.
The shared registry reader preserves existing startup rows while adding mechanism
provenance. Freshness/domain aggregation and host/guest capture tooling include
the new sources and the preceding module wave.

The native fixture creates only an owned inert scratch hierarchy, not actual
activation/autorun configuration. Consolidated Release CTest passed 44/44;
the 20-second host endpoint run retained seven complete page assemblies and
7,529 original records across two identical recovery readbacks. This verifies
capture assembly, not complete native/domain enumeration: native access failures
and COM branch truncation remain explicit. Thread, module and memory workers
now have distinct retained capture sets; the first eight host module/memory
candidates all refused access, so successful runtime metadata for those two
sources is not established by that host run. Refer to the newest validation
entry for consolidated guest results and remaining gates.

## Standalone breadth continuation - 2026-10-22

The current wave adds native browser profile manifest inventory, browser/Office
registration context, read-only Defender preferences, configured-root FIM and
ETW ownership recovery. Read APPLICATION_CONTEXT.md, BROWSER_INVENTORY.md,
DEFENDER_PREFERENCES.md, FILE_INTEGRITY.md and ETW_SESSION_OWNERSHIP.md.
The runtime now dispatches nine persistence sources plus separate identity,
software, thread, memory, module, browser-profile and Defender-preference workers.
FIM is disabled unless --fim-root supplies explicit absolute local directories
(up to eight); monitoring is direct-child only, with no recursive claim.

The combined main executable compiles; new collectors/recovery have not been
runtime verified. The user explicitly deferred further testing until a final
integration stage. Keep this debt visible rather than treating compilation or
historical passing suites as current evidence. The prior guest retry terminated
with partial state success and process ETW failure from a historical fixed-name
orphan. New session ownership code never blindly stops that legacy session.

Next priorities remain native continuous network/DNS, response durable lifecycle
and target safety, lifecycle/reconciliation, source-loss/resource controls,
signed policy/update boundaries, and consolidated Windows fault/restart/security
qualification. Do not deepen integration with the current Detection Engine.

## Registry change notifications continuation - 2026-10-22

Added a read-only, independent `RegNotifyChangeKeyValue` source and durable
consumer for selected HKLM/current-caller persistence, service and LSA
subtrees. It records subtree signals and collector queue-loss gaps only; it does
not expose value diffs, changed descendants, writer identity or exact Windows
change counts, and it does not launch the requested reconciliation. See
[registry change notifications](REGISTRY_CHANGE_WATCH.md). No build, test or
runtime validation was run in this wave; native API hard deadlines and bounded
shutdown remain open.

## WFP isolation continuation - 2026-10-22

The isolation action now atomically replaces its IPv4/IPv6 ALE policy, scopes
outbound Manager reachability to one numeric IP plus TCP port, removes the old
address-wide v1 exception during migration and rolls back on failure. See
ISOLATION.md. This source compiles only when the next consolidated build is run;
no tests or live adapter validation were performed. Do not advertise reboot
persistence: current filters survive process restart but do not use WFP reboot
persistence flags. Signed recovery and actual enforcement qualification remain
open.

PowerShell semantics are now integrated through the existing native log decoder;
read-only channel and script-logging policy observations are surfaced in health.
No channel/policy activation is performed. Component/Windows validation remains
pending final integration.

## Standalone capability breadth wave - 2026-10-22

The current unvalidated code wave adds configured-root Windows DNS state
inventory and connects continuous IP Helper interface/address/route changes to
the durable endpoint record path with initial snapshots, a manifest, queue-loss
gaps and shutdown draining. Its runtime/queue behavior has not been built or
executed. Additional in-progress isolated slices cover signed desired/effective
configuration, Security event actor/target semantics, encrypted file evidence,
typed forensic response routing, and SCM change notifications. These pieces are
not yet an integrated release: treat each one as implemented at source level
only unless its own ledger entry later records stronger evidence. Builds and
tests are intentionally deferred to the user-requested final integration stage.

## SCM service-state change source - 2026-10-22

`ServiceStateChangeSource` uses Windows SCM per-service status notifications,
plus bounded periodic enumeration to discover service names created after the
last pass. It is wired into CMake and the runtime after service inventory. The
runtime retains begin/reconciliation/change records and gap records through
the endpoint journal, holds at most one immutable refused record, projects
source loss and service status into health, and cancels subscriptions before
joining and draining at shutdown. See `SERVICE_STATE_CHANGES.md`.

This source is source-level implementation only. No build, component test,
Windows VM, restart, churn, privilege, failure or shutdown validation has been
run. Never report continuous/full SCM lifecycle coverage from this API: status
notifications are per-service, new names are discovered periodically,
configuration changes and driver load/unload are outside its scope, and PID is
not a process-instance identity. If subscription handles fail/recreated
services are missed or callback/enumeration loss is recorded, keep service
coverage blind/degraded. Reassess the bounded stop drain's pending-record and
loss accounting during final integration.

## Update-package staging core - 2026-10-22

AJ now has an isolated `UpdatePackageStore` source core registered in
`officer-core`. A caller-provisioned ECDSA P-256 publisher pin verifies a
canonical, closed, bounded manifest. The stage operation binds generation,
architecture, version, size and SHA-256 to a file copied into a pre-created
local fixed-volume root; generation high-water, previous signed package
metadata and rollback intent are committed atomically under a process lock.
It does not install or execute packages. See `UPDATE_PACKAGE.md`.

This is source-level only, unbuilt and untested. Do not claim secure update,
deployment, installation, or rollback capability: independent trust-root
provisioning/rotation, root ACL provisioning/runtime verification, authenticated staging and
rollback authorization, installer/MSI/service migration, boot recovery and
Windows fault/compatibility qualification remain open.

## Windows Event Log generation and retention lifecycle

A code-level lifecycle reconciliation wave adds a versioned native bookmark
cursor bound to channel creation time and last accepted record ID, per-channel
source gaps, and reset-to-oldest recovery for detected generation changes,
malformed/stale cursors, ID regression and estimated retention overwrite. Gap
and replacement cursor use the same durable source-checkpoint acceptance. Legacy
native XML bookmarks migrate with an explicit generation-unknown gap. This is
not verified: do not claim real Windows clear/recreate/rollover/retention
continuity. Native provider loss count/ranges remain unknown or approximate.
No build, component test, or Windows runtime validation was run in this wave.

## Browser profile-directory discovery - 2026-10-22

Browser extension metadata collection now also examines a bounded set of
direct, non-reparse profile-directory candidates under the configured Windows
profiles root, using conventional AppData-relative browser paths. The current
process token is the only access authority; directories are not associated with
account SIDs, and access refusals remain visible. Production page paths are
removed and replaced by per-capture salted pseudonyms where system randomness
is available. This is not all-user inventory: relocated roots, profiles outside
the configured directory and inaccessible metadata are out of scope. Native
profile discovery, privacy output, linking, durability/restart, boundedness and
OS compatibility have not been built or tested. Do not claim all-user browser
coverage. See [browser inventory](BROWSER_INVENTORY.md).

## DNS Client event semantics - 2026-10-22

The existing DNS Client Operational subscription remains unchanged and retains
the same raw XML/EventData, bookmark, durability and per-channel health flow.
The shared decoder now labels only exact provider `Microsoft-Windows-DNS-Client`,
channel `Microsoft-Windows-DNS-Client/Operational`, event ID 3008 as
`dns_query_completed`, following Microsoft's WEF guidance. It does not parse
the query/result fields or attribute the lookup to a process; the event writer
PID/TID remain unverified writer metadata. This source-level decoder addition
is unbuilt and has no enabled-channel validation. See [DNS state](DNS_STATE.md).
The separate DNS state/configuration collector does not collect query names or
answers, but enabled DNS Client Operational events can retain query content in
raw XML/EventData (including QueryResults). Treat those originals as potentially
sensitive; the decoder neither interprets nor attributes the content.

## SCM service security and configuration metadata

Durable service inventory pages already include selected owner/group/DACL and
independent bounded native settings for failure actions, service SID type,
launch protection and triggers. A new source-only decoder addition reports
standard ACE raw masks and recognized service-right bits, preserves unclassified
bits, and adds per-optional-level native OS/service applicability hints with the
exact query error retained. No build or runtime validation was performed. Do not
claim effective ACL decisions, trustee/account resolution, SACL/label coverage,
running service identity, or PPL readiness. See SERVICE_STATE.md.

## AJ publisher trust-bundle lifecycle

Added a source-level, caller-bootstrap-pinned trust store with canonical bounded
keysets, P-256 SPKI identity validation, monotonic generations and fork/replay
refusal, activation/retirement/revocation timestamps, 24-hour planned key
rotation overlap, and ACL-checked atomic persistence. State reports `unknown`
when absent and `unavailable` on invalid/expired/unreadable data; those states
never provide active publisher pins. It is not wired to the static-pin
UpdatePackageStore yet. Caller provisioning, dynamic verifier binding, native
build/runtime and crash-recovery validation remain required. See
UPDATE_PACKAGE.md.

## Recursive configured-root FIM wave - 2026-10-22

Explicit FIM roots now enable bounded recursive baseline and `ReadDirectoryChangesW` subtree notifications by default; callers can opt out to preserve direct-child scope. Traversal tracks directory identities, refuses reparse points and reports depth, directory, entry, path, overflow, restart, scope-change, and root-change gaps. Reconciliation is limited to a fresh bounded baseline and is non-atomic; notification records do not verify actor or exact rename pairing. This source wave is unbuilt and untested; do not claim full filesystem coverage or OS qualification. See [FIM](FILE_INTEGRITY.md).

## Task Scheduler Operational event semantics - 2026-10-22

The existing `Microsoft-Windows-TaskScheduler/Operational` pull channel now
classifies only provider `Microsoft-Windows-TaskScheduler` event IDs 106, 141
and 142 as task registered, task registration deleted and task deleted, based
on Microsoft's Windows Event Forwarding intrusion-detection guidance. Rendered
XML and ordered raw EventData are preserved. The guidance does not specify
EventData field templates, so no fields are interpreted and writer PID/TID or
Security UserID do not establish actor/process identity. The existing bookmark,
journal, channel subscription and health path is unchanged. Source changes have
not been built or runtime-validated; enabled-channel coverage and provider
version compatibility remain open. See [native event logs](WINDOWS_EVENT_LOG.md).

## WMI-Activity Operational event semantics - 2026-10-22

The existing `Microsoft-Windows-WMI-Activity/Operational` pull channel now
classifies only exact provider `Microsoft-Windows-WMI-Activity` events 5857 and
5858 as `wmi_provider_started` and `wmi_client_operation_reported`, based on
Microsoft Learn guidance. Rendered XML and ordered raw EventData remain intact;
no fields are interpreted. Reported User/ClientProcessId values and writer
metadata do not establish actor/process identity or correlate the event to the
permanent subscription inventory. The existing subscription, bookmark,
journal and health paths are unchanged. No build, tests or runtime validation
were performed; provider/version compatibility remains open. See [native event
logs](WINDOWS_EVENT_LOG.md).

## AJ active publisher trust integration

`UpdatePackageStore(root, PublisherTrustStore&)` now reads the latest trust
snapshot under the shared staging-root lock, accepts only currently active
authenticated publisher pins for new package manifests, and fails closed for
unknown/unavailable/expired trust. Current and previous package metadata retain
the exact signed trust bundle used at package issue time; durable high-water and
rollback validation verify key validity from that provenance across rotations.
The legacy static-pin constructor is deprecated and has no activation/revocation
semantics. This remains source-level only and untested. Bootstrap provisioning,
authenticated trust-bundle installation, installer integration and runtime/power-
loss qualification are still external work. See UPDATE_PACKAGE.md.

## Socket process identity sampling - 2026-10-22

Each decoded native socket row now receives separate held-handle process
identity evidence: recheck PID with `GetProcessId`, read creation FILETIME from
the held handle, and derive exact host/boot/PID/time entity identity only when
native boot identity is available. Query results are cached per native table and
PID with a 4,096-entry bound. Preserve the original null process reference and
the warning that native socket-table capture and process sampling are not
atomic; this does not prove socket ownership at the table observation instant.
No build, tests or real-Windows validation were run. Validate rapid process
churn/reuse, query refusal, missing boot identity, accepted-page contracts,
resource cost and serialization at final integration. See SOCKET_STATE.md and
VALIDATION.md.

## Scheduled-task structure summary - 2026-10-22

The task-definition parser now exposes bounded action/trigger kinds and counts,
principal field presence, and selected setting-field presence alongside the
existing unchanged XML. It does not duplicate configured identity strings,
command arguments or trigger expressions, and it does not assert execution or
effective authorization. Limits are 128 actions, 128 triggers and 16 principals.
Assertions were added to the component test source but intentionally not run per
the current defer-testing instruction. Build and Windows runtime validation are
still required. See PERSISTENCE_STATE.md.

## Durable source supervision baseline - 2026-10-22

Collector-status comparison checkpoints now use DurableJournal CAS persistence.
Gap transitions checkpoint immediately; otherwise-quiet status checkpoints at
most every 30 seconds without emitting records. Any gap observation and the checkpoint that follows it commit in one transaction.
Retries preserve bytes and revision. A new collector generation intentionally
starts an unknown comparison interval, avoiding false counter deltas across
process lifetimes. No build/tests/runtime validation were run. See
DURABLE_SOURCE_SUPERVISION.md and VALIDATION.md for limits and final-stage
scenarios.

## Security product registration inventory - 2026-10-22

A new IWSCProductList collector enumerates bounded caller-visible firewall,
antivirus and antispyware registrations and retains product name/GUID, reported
state and signature status, timestamp, remediation path, and default flag with
per-call HRESULTs. The five-minute worker commits immutable records before
health/freshness is reported. This is WSC registration evidence, not product
attestation or effective protection. Server contract, native-call deadlines,
product signer/version verification, tamper enforcement and runtime qualification
remain open. It has not been built or tested. See SECURITY_PRODUCTS.md.

## Firewall rule-inventory bounds and privacy review - 2026-10-22

The shared checkout already has a separate read-only `INetFwPolicy2::get_Rules`
worker, independent from profile snapshots. It queries selected base and
extension fields with per-getter HRESULTs; limits strings to 8 KiB each and
64 KiB per rule, rows to 256 KiB, pages to 64 rows/512 KiB, captures to 8,192
rows/256 pages, and releases each row's COM references before durable page
admission. A dedicated durable begin/page/manifest flow exposes health only after
acceptance. No policy setters are used. This wave made documentation-only
clarifications and ran no build/tests/runtime. Native COM allocations/call
deadlines, effective Group Policy/filter provenance and packet enforcement
remain unqualified. Rule text can expose paths, services, addresses, ports and
authorization/package information and is retained without redaction. See
[firewall rules](FIREWALL_RULES.md) and [firewall profiles](FIREWALL_STATE.md).

## Quarantine handle and outcome wave - 2026-10-22

`QUARANTINE_FILE` now verifies source identity from a held handle, rejects
reparse targets and root redirection, requires the source under the held
collection root, and refuses cross-volume moves. It tightens the source DACL
before an atomic, handle-relative same-volume rename that cannot overwrite an
existing destination. Metadata uses a unique `CREATE_NEW` staging file, a
flush, and a no-clobber rename. `QuarantineOutcome` explicitly reports
`refused`, `failed`, `partial` or `completed`, including whether the source
security changed, the source moved, destination protection was applied, and
metadata was flushed. The response dispatcher must pass this output and map
post-mutation `partial` to `indeterminate`; the dispatcher integration is now
present in source but has not been built or runtime validated. No build, tests
or Windows runtime validation were run. Directory
entry durability under power loss and protection of the quarantine parent
directory remain open. See PROCESS_RESPONSE.md and VALIDATION.md.

## WFP Security audit event semantics - 2026-10-22

The separate `SecurityAuditSemantics` enrichment now labels exact Security
channel/provider events 5152, 5156 and 5157 as WFP blocked packet, permitted
connection and blocked connection source events. Microsoft event-specific
references are linked in [WFP audit events](WFP_AUDIT_EVENTS.md). The enrichment
preserves raw XML/EventData and performs no field, endpoint, process or actor
interpretation. Audit policy is not changed. No build, tests or Windows runtime
validation were run; enablement, high-volume behavior, provider/version coverage
and attribution remain open.

## WFP isolation key ownership reconciliation - 2026-10-22

Isolation now validates v2 filter-key ownership by expected sublayer before
delete/replacement/release, checks legacy filters against their legacy
sublayer, validates an existing v2 sublayer's expected display identity, and
fails closed on `FWP_E_ALREADY_EXISTS` after reconciliation. This closes
accidental key collisions and false-success when the expected filter key is
occupied. It is source-only: no build, tests, or live Windows enforcement
verification. Provider identity, privileged tamper resistance, BFE recovery,
reboot persistence, third-party WFP coexistence, and signed offline release
remain unqualified. See ISOLATION.md and VALIDATION.md.
## Secure Boot firmware variable host-state increment — 2026-10-22

The host snapshot now includes an independent read-only `GetFirmwareEnvironmentVariableExW`
query for UEFI global `SecureBoot`, alongside firmware type and caller token
privilege evidence. Existing `UEFISecureBootEnabled` registry evidence remains
separate; comparable values produce an explicit agreement/disagreement result.
The worker does not enable privileges or mutate firmware. Only a one-byte 0/1
value is interpreted; access denial is blind, legacy BIOS is unsupported, and
missing/unknown data does not imply Secure Boot is off. This change is source-only
and unvalidated. Next, build and exercise under non-elevated and properly
authorized tokens on BIOS/UEFI Windows guests, including API-error and registry
mismatch cases; do not claim Secure Boot attestation or key database coverage.

## Volume encryption WMI status - 2026-10-22

A separate read-only `Win32_EncryptableVolume` state worker queries
`ROOT\CIMV2\Security\MicrosoftVolumeEncryption`, captures a bounded set of
volume identifiers, and invokes only `GetProtectionStatus`,
`GetConversionStatus` and `GetEncryptionMethod`. Exact WMI call HRESULTs,
provider `ReturnValue` values and output-field HRESULTs are retained separately.
The five-minute durable worker exposes query health only after record acceptance;
no state-changing BitLocker method is called. This source has not been built,
tested or run on Windows. WMI/service/privilege support, physical volume mapping,
hardware encryption, key-protector/recovery/escrow coverage and hard WMI call
deadlines remain open. See [volume encryption](VOLUME_ENCRYPTION.md).

## Publication handoff checkpoint — 2026-10-22

The current uncommitted wave is being prepared for teammate continuation from
the verified `origin/main` baseline `b72e2affd1ee6042167deb6d94f5a8feecdf7b84`.
Source-level additions span durable source-loss checkpointing, response and
forensic file handling, WFP isolation ownership, host/security-product/volume
state, DNS and remote-access inventory, persistence/service/network change
sources, event semantics, configuration and package-update primitives, and
socket owner-process sampling. The detailed capability matrix and validation
ledger identify each source-only increment. The QUARANTINE_FILE result is now
passed through response dispatch: refused/failed/partial outcomes map to
non-success receipts, and partial mutation details are retained in the receipt.

Two in-progress areas must not be treated as complete. `src/collectors/usn_journal.cpp`
contains an incomplete bounded volume-rediscovery redesign. It has not been
built; finish its worker/discovery concurrency and lifecycle review, update the
public header and USN documentation, and validate hotplug/removal/reappearance
and unknown-interval behavior before claiming the gap closed. Sysmon EID 8/10
process-interaction telemetry is not implemented end-to-end; an incomplete raw
variant scaffold was removed because adding a variant without all visitors and
serializers could break the build. Complete the Windows-specific body through
decoder, source facts, normalization, canonical serialization/schema, durable
dispatch, and evidence. Remote-access inventory currently covers SMB only;
RDP and WinRM listener state remain open, with local WSMan enumeration identified
as a supported candidate for WinRM.

No build, unit test, full test suite, or VM validation was run in this wave, per
the user's request to defer consolidated testing until the planned development
is complete. Do not describe these source changes as compiled or verified. The
complete A–AN Definition of Done remains unmet. First review and finish the
partial items above, then continue broad endpoint implementation; only after the
coding phase should the team run a consolidated build/test and real-Windows VM
qualification pass. The nested `.claude/worktrees` directory and Python
`tools/__pycache__` are local/generated artifacts and are not endpoint source.
