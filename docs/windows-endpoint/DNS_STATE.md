# Windows DNS configuration state

`collect_dns_state_pages` is a read-only, bounded snapshot collector. It emits zero or more `paged_dns_state_v1` pages, then returns a `dns_state_version: 1.0` capture manifest. The manifest and each page state `inventory_complete: false` and `consistency: non_atomic`; a successful enumeration means only that the collector completed its listed queries and copied their bounded outputs.

## Sources and captured fields

- **Adapter resolver view:** `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES)` supplies caller-visible adapter indices, LUID, status, suffix, DNS server socket addresses, and adapter names. These fields are scoped to the API's caller context and returned interface set. Adapter listing order or operational status does not establish which resolver Windows would select for a particular name.
- **Interface DNS settings:** For each adapter whose `AdapterName` parses as a GUID, `GetInterfaceDnsSettings` version 3 is queried read-only. Returned domain, static/profile name servers, connection-specific and supplemental search lists, registration/adapter-name flags, LLMNR/mDNS setting, and DoH server properties are preserved with the API provenance. Template strings and property arrays are bounded before copying. A refused or unsupported interface query is reported on that adapter; it does not erase fields returned by `GetAdaptersAddresses`.
- **Global configuration:** Selected values (`Domain`, `SearchList`, `DhcpDomain`, `UseDomainNameDevolution`, `EnableMulticast`, and selected DoH policy/template names) are queried from three local machine registry paths listed in the implementation. Values are tagged as raw registry configuration. Missing keys/values are `not_present`; access/query failures and unsupported types remain explicit.
- **NRPT:** Selected fields are read from the machine Group Policy and DNS Client service `DnsPolicyConfig` roots. The collector records raw persisted rule values and the registry subkey index. Registry order is not represented as precedence, and these roots are not treated as a merged active NRPT view. Each root independently reports missing, failed, complete, or bounded enumeration state.
- **Machine-wide DoH catalog and DNS cache:** The collector explicitly reports that the machine-wide merged DoH template/policy catalog is unavailable from this capture. It does not enumerate cache names, records, answers, TTLs, or other full cache content; no cache metadata-only query was used because this collector has no documented bounded metadata-only source.

## Bounds, capture flow, and refusal semantics

Defaults cap the adapter input buffer at 1 MiB, adapter count at 1,024, NRPT subkeys at 2,048, pages at 256, entries per page at 64, encoded page payload at 512 KiB, copied fields at 16 KiB, and a 30-second soft budget. Caller-supplied limits are clamped to implementation maxima. The adapter query uses a caller-owned fixed buffer; if Windows reports `ERROR_BUFFER_OVERFLOW`, the complete adapter result is refused and the required size is reported without retrying with an unbounded allocation. API-internal allocations, registry/Win32 work, and call duration cannot be hard-bounded by this wrapper.

Pages are delivered before the returned manifest. A consumer refusal stops further collection and sets `consumer_refused`. Cancellation and soft-budget expiration stop new queries and set their respective flags. A row/field/page/count limit sets `bound_exceeded`; values that cannot be safely copied are represented as null with degraded/unavailable state and an explicit bound or error code. Per-source partitions retain their own result even if another source fails. The manifest only marks enumeration complete when no such refusal, bound, cancellation, timeout, adapter decode issue, or source failure was observed.

This collector does not change DNS servers, suffixes, NRPT, DoH configuration, cache state, adapter state, or network behavior.

## DNS Client Operational event semantics

The existing `Microsoft-Windows-DNS-Client/Operational` pull subscription
continues to retain rendered event XML and ordered raw EventData. The decoder
now labels Event ID 3008 as `dns_query_completed` only when the requested and
native channels are exactly `Microsoft-Windows-DNS-Client/Operational` and the
provider name is exactly `Microsoft-Windows-DNS-Client`. Microsoft Learn's
Windows Event Forwarding example calls event 3008 “Query Completed” and uses
the named `QueryOptions` and `QueryResults` fields in filters. The decoder does
not interpret those values, infer success from completion, or transform query
names/results; all fields stay available in the original XML/EventData.

Attribution remains explicitly unverified. The event writer PID/TID are kept
as writer metadata and are not treated as the process that requested the DNS
query. `dns_client_semantics` carries a null subject process ID and states this
uncertainty. No process-instance join or per-query socket correlation is done.
Other DNS Client event IDs and nonmatching channel/provider pairs remain
unclassified. This is source-level decoder support only: the existing channel
subscription owns its normal health, bookmark, refusal and durability path, but
no event from an enabled DNS channel was collected or validated in this wave.

## Interpretation limits

This is not a resolver decision engine and it does not prove the effective resolver for a queried name, winning NRPT rule, all network compartments, all user/device policy layers, per-query DoH/DoT use, proxy or application-specific DNS, or name-to-connection/process attribution. DoH details are reported only where the per-interface API returns them. This state/configuration collector does not acquire DNS query names or answers. Separately, the existing DNS Client Operational event source can retain such content within its raw rendered XML/EventData (including QueryResults where present); that content is not interpreted or attributed to a requester by the decoder. Raw DNS event retention therefore carries query-content privacy and retention risk and is subject to the event source's channel enablement, permissions, loss, and retention behavior. Cache visibility remains explicitly unavailable.

Relevant Microsoft API contracts: [GetAdaptersAddresses](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses), [GetInterfaceDnsSettings](https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings), [DNS_INTERFACE_SETTINGS3](https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings3), and [DnsQueryConfig](https://learn.microsoft.com/windows/win32/api/windns/nf-windns-dnsqueryconfig). `DnsQueryConfig` documents `DnsConfigSearchList` as not implemented; this collector therefore uses source-tagged adapter, interface, and registry values and does not synthesize an effective search list.

Event label source: Microsoft's [Windows Event Forwarding guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-intrusion-detection) selects `Microsoft-Windows-DNS-Client/Operational` event 3008 and labels it “Query Completed”; it also references `QueryOptions` and `QueryResults` for filtering. This agent uses only the event/channel/provider label and preserves those fields raw.

## Endpoint integration and evidence

The collector is registered in `officer-core` and the periodic native state
worker emits bounded page records, a capture manifest, record-bound health and
freshness under the DNS state category. It remains a state/configuration view;
the DNS Client Operational log is an independent event source. This integration
has not yet been built or run on Windows in the current wave. API return behavior,
DoH settings, NRPT visibility, page refusal, journal refusal, restart continuity,
resource limits and OS compatibility remain unverified.
