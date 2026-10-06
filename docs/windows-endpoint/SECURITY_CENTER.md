# Windows Security Center category state

An independent read-only worker captures six WscGetSecurityProviderHealth category
reports initially and on a nominal five-minute schedule: firewall, automatic
update settings, antivirus, Internet settings, User Account Control and the WSC
service. Every query uses its individual provider mask; categories are not
collapsed into a single worst-health result. Legacy anti-spyware is omitted;
Microsoft stopped tracking that category starting with Windows 10 version 1607.
The API has a client contract and no supported Windows Server contract. Separate
Server/product-specific visibility remains required. See
[provider categories](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider).

Version 1.1 queries RtlGetVersion with the extended native version structure,
retaining version/product-type raw values, query windows, exact NTSTATUS and
separate Win32 resolver failures. A verified workstation at the documented
minimum is contract-eligible, not platform-qualified. Server/domain-controller
types or a pre-Vista client are explicitly unsupported for this API. Failed,
unknown/sentinel or nonzero successful version results leave contract eligibility
unknown; they never become inferred Server evidence. The core ntdll handle is
borrowed and not released. See
[native version query](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion).

Unsupported contract classification does not suppress descriptive native WSC
queries. It preserves raw outputs, HRESULTs and native_query_state, keeps any
recognized enum label in native_reported_health, and leaves reported_health null.
This prevents an outside-contract success from becoming trusted protection
posture while retaining the evidence. Only the WSC capability/category is marked
unsupported. Q.security_product becomes unavailable for this source; the broader
Server security-product objective still requires independent supported sources.
Native version and local DLL reports are not attestation or proof against hooks.

Native loading uses LoadLibraryExW with System32-only search and resolves the
optional export dynamically. Missing module/export records native Win32 error
codes and leaves six getters unattempted with null HRESULT/output. WSC is not a
static startup dependency. The DLL reference is released after queries; loading
does not attest the DLL/server integrity or bound native call duration. No
service, monitoring setting, product registration or protection policy is changed.

Each attempted getter retains exact unsigned decimal HRESULT, requested mask,
query uptime window and raw successful output. Recognized S_OK enum values retain
good, not_monitored, poor or snooze reports. Field `state` describes query quality:
a successfully read poor report can have healthy query quality. It never proves
protection. S_FALSE means WSC service unavailable; its documented fallback POOR
value stays raw with null reported_health. An unexpected S_FALSE output has a
separate validation error. Failed HRESULTs leave output/interpretation null.
Unknown/sentinel outputs and other successful HRESULTs remain degraded, with
original values intact. Counts separate S_OK, S_FALSE, failures, other success,
unknown outputs and unattempted queries. See
[API semantics](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/nf-wscapi-wscgetsecurityproviderhealth)
and [reported health values](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/ne-wscapi-wsc_security_provider_health).

The canonical security_center_state record must reach the journal before matching
health and state.security_center/category coverage are exposed. Refusal retains
identical pending record bytes/identity. Q.security_product remains partial;
inventory_complete, protection_verified and individual_products_collected stay
false. Queries are sequential/non-atomic and aggregate categories describe no
verified product, process or file lifetime. The worker participates in the ten
state sources' record-bound capture freshness and sampled transition history.
Other workers continue independently when these queries fail; whole-process,
native call and journal blocking deadlines remain unqualified.

Native tests cover separate masks, recognized reports, failure, sentinel/unknown
output, nonzero success, S_FALSE with both documented and unexpected output,
missing API and actual read-only category capture. Canonical fixtures cover
schema, immutable Manager/readback and unchanged Detection data without an actor.
An owned agent's abrupt-exit/reopen checks exact snapshot and record-bound health,
including all ten state domains with unread diagnostic output.

Individual registered product identities/versions/signers/state, Defender
configuration and exclusions, ASR/SmartScreen/tamper/EDR mode, third-party
coexistence, monitoring policy provenance, native WSC change notifications,
state reconciliation, Server fallback, native loader/getter fault and deadline
experiments, OS/ARM64/security-configuration/resource/soak and analyst presentation
remain required. This collector reports Windows posture; it does not register
Panopticon as an antivirus or make an antivirus product part of local prevention.
