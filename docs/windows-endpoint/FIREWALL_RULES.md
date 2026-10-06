# Caller-visible firewall rule inventory

An independent worker captures `INetFwPolicy2::get_Rules` and its `INetFwRules`
enumerator initially and on a nominal five-minute schedule. It commits a begin,
ordered pages and a manifest before exposing matching health and
`state.firewall_rule_inventory` coverage. Every pending canonical record retries
identical bytes/identity after journal refusal. Accepted page IDs are retained in
manifest order. Interrupted captures, native getter deadlines, resource faults,
durable intent and lifecycle reconciliation remain unqualified.

Native collection initializes and balances its own COM apartment reference and
releases local interfaces on scope exit. Setup HRESULTs, separately queried rule
count, the last enumeration HRESULT/fetched count and native Next-call count are
retained. A successful native result without the requested interface is a
validation failure, preserving the successful HRESULT. IEnumVARIANT completion
requires S_FALSE with no fetched item; other progress combinations are explicitly
uninterpreted. Both dispatch and unknown rule objects are queried for INetFwRule.
Uninterpreted/unavailable objects remain descriptive rows with null identities.
No firewall rule, group or policy is added, removed or changed. See
[the rule collection](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrules)
and [its enumerator](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-get__newenum).

All 18 base properties are queried independently: name, description, application,
service, protocol, local/remote ports and addresses, ICMP types/codes, direction,
interfaces and interface types, enabled, grouping, profiles, edge traversal and
action. Facts retain exact HRESULTs, query windows, raw output, recognized typed
interpretation and unknown/refused fields. Noncanonical booleans and unknown
enums remain degraded. Optional/null text stays explicitly unknown; it is not
implicitly turned into a wildcard. Ports/addresses/group strings are preserved
without inventing effective match semantics. Profiles retain the original mask,
including the ALL sentinel. Friendly interface names use bounded borrowed COM
array decoding; they do not become verified interface lifetimes.

Collector version 1.1 additionally queries seven INetFwRule2/3 properties:
edge traversal options, local app package identifier, local user owner,
local/remote user authorization lists, remote machine authorization list and
IPsec secure flags. Both extension interface queries are independent and retain
their own HRESULTs and query windows. E_NOINTERFACE means unsupported; other
refusals mean unavailable. Successful interface queries returning null preserve
their successful HRESULT with a separate validation error. Dependent getters
remain explicitly unattempted with null HRESULT/value; base getters continue.
Summary unattempted counts are separate from actual successful/failed getters.
Extension strings share the same per-rule text-copy budget as base strings.
SDDL/SID/package text remains descriptive, with no verified principal, package
or effective authorization join. Unknown edge/IPsec enum values retain raw output.
See [INetFwRule3](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule3),
[edge options](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule2-get_edgetraversaloptions)
and [IPsec requirements](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_authenticate_type).

BSTR getters retain embedded NULs and malformed/odd text as raw bytes; copies are
bounded to 8 KiB per string and 64 KiB of text per rule. Native allocations are not
bounded by those copy limits. Row encoding is bounded to 256 KiB; pages contain
at most 64 rows/512 KiB of encoded entries, with 256 pages and 8,192 rule rows per
capture. A refused/oversized candidate is not credited as delivered. Queried and
accepted rows, produced pages, consumer refusal and bounds remain separate from
source telemetry loss. Getter summaries include queried objects whose rows may
not have been delivered. JSON/allocator/thread memory is not a hard RSS budget.
Each row's COM references are released before consumer journal I/O; the enumerator
still exists across paging, and collection remains non-atomic.

Rule names, paths, services and enumeration ordinals are descriptive evidence.
`rule_reference` and `process_reference` remain null. A count observed before
enumeration cannot prove a complete/atomic snapshot. `inventory_complete` and
`effective_packet_policy_verified` remain false even when every enumerated row
was durably accepted. Service-hardening filters,
Group Policy/MDM/local-store provenance, dynamic/effective WFP filters, verified
rule/interface/file/process relationships, third-party enforcement, changes and
analyst capture assembly remain required.

Tests exercise encoded-byte-driven paging, duplicate descriptions without
identity, exact accepted prefixes after consumer refusal, oversized rows,
unavailable enumeration and actual read-only native collection. Canonical native
fixtures preserve begin/page/manifest relationships through contract validation,
Manager ingestion/readback and unchanged Detection data. Runtime qualification
uses an owned agent, abrupt exit and only its stopped journal, checking exact
page/manifest/record-bound health recovery. Whole endpoint/OS/security-configuration,
tampering, sustained load, deadlines and soak gates remain open.

An owned detached rule object exercises native extension getters and descriptive
owner text. It is never registered in INetFwRules; test setters affect only that
object. Injected interface queries exercise unsupported/access-refused/null
success outcomes without suppressing base getters. Native extension getter
failure, sentinel/unknown outputs, text/aggregate limits and COM deadline/resource
fault qualification remain open.
