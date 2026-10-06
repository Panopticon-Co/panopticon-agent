# Native route state

An independent worker queries GetIpForwardTable2 separately for IPv4 and IPv6.
Each family carries the exact native return code, query window, reported row
count, decoded count, accepted page count and narrowly scoped coverage state.
Tables are captured in the caller context; compartment identity and completeness
across compartments remain unverified/null. No compartment-changing API is used.
The current Microsoft documentation marks GetCurrentThreadCompartmentId reserved
for future use and directs applications not to use it.

Rows preserve reported interface LUID and index as full-width decimal strings.
These describe the native route/interface association; persistent interface and
route-instance references remain null. No join to a later adapter snapshot is
asserted, and no process actor is invented. Interface indices are not persistent.
Destination and next-hop addresses preserve network bytes for known IPv4/IPv6,
including IPv6 scope and flow values. Unknown families retain the raw family
value with unavailable/null address interpretation, and do not serialize
inactive address unions or padding. Prefix lengths are checked against the
address family. The documented invalid site-prefix sentinel 255 remains raw,
with degraded interpretation. No destination text or default route selection
is inferred from unknown fields.

All lifetime, age and metric values remain native decimal strings. Infinite
lifetime sentinel 4294967295 is retained without deriving a wall-clock expiry.
The route metric is only an offset; effective_route_metric remains null because
later interface metrics do not verify route/interface lifetime or the selected
routing decision. Version 1.1 records a separate reported_metric_sum when the
later lookup fields match and the offset is not the unused 4294967295 sentinel.
The full-width sum is arithmetic on separately observed facts, not an effective
path claim. Raw protocol,
origin and BOOLEAN bytes are retained alongside recognized symbols/values.
Unrecognized enums, noncanonical BOOLEAN bytes, inconsistent address families
and invalid prefixes degrade the row/table rather than substituting defaults.
These are reported fields, not proof of effective access or a packet's path.

GetIpForwardTable2 owns its native allocation and does not report its byte length.
The collector uses SDK table/row alignment and frees the API allocation with
FreeMibTable through RAII. A successful table is trusted as an OS-provided array;
there is no claim of independent validation of its allocation extent. Reported
count is checked before copying or row reads. At most 65,536 rows and 8 MiB of
native copied row data per family are permitted; excessive counts are refused
with the original count and validation/bound status. The native allocation is
already made before these limits apply, so native_allocation_bounded is false.
The API allocation is released before durable page callbacks run. Copied native
structure bytes are temporary; only defined fields are serialized, without
claiming retention of original padding bytes.

Each page has at most 256 rows and 512 KiB encoded entry data, with a 4,096 page
limit. Decoded/queried rows are separate from accepted pages. Consumer refusal
cannot count unaccepted rows as delivered; later family queries are explicitly
not attempted. Native ERROR_NOT_SUPPORTED maps to unsupported; other failures
retain unavailable/null and the returned Win32 code, including native
ERROR_NOT_FOUND rather than silently declaring a complete empty census.

Canonical route_inventory_begin, ordered route_inventory_page records and an
exact-ID route_inventory manifest commit through the encrypted journal before
stdout. Stable bytes and IDs retry on admission failure. An independent
five-minute refresh follows a committed manifest. Health retains the exact
manifest ID and query status, pending acceptance, page and commit counts.
state.route_inventory remains degraded/unavailable; state.route_table.ipv4/ipv6
can be healthy only for the narrowly scoped family query/recognized values/page
acceptance. Event-source startup failure does not prevent route capture. A
captured table's health does not claim fresh continuous change coverage.

Native tests cover full-width LUID/index/metric/lifetime fields, truncated rows,
unknown enums and flags, invalid prefixes, native access denial, excessive row
counts and refusal after an accepted prefix, plus actual read-only native
collection. Manager tests validate the published canonical schema, preserve
the exact accepted wire body/digest and pass unchanged data to Detection without
an invented actor. The owned-process crash/reopen harness binds health and table
counts to exact durable pages and manifest. No routes are created, modified or
deleted by collection or its tests.

Independent IP interface table census is now a separate capture described in
[IP interface state](IP_INTERFACE_STATE.md). Complete link-layer/physical
interface state, verified lifetime/compartment and effective
path relationships, change notifications/reconciliation, proxy configuration,
DNS, firewall posture, hard native allocation/deadline limits, crash/gap intent,
durable loss accounting, freshness, privilege/OS/ARM64/resource/storm/soak and
analyst capture assembly remain open. Full network EDR coverage and endpoint
Definition of Done are unqualified.

Version 1.1 adds GetIpInterfaceEntry queries for route-associated IP management
state. A capture caches at most 512 unique family/lookup keys. Nonzero LUID is
used preferentially with native input index zero; index fallback occurs only
when the reported LUID is zero. Later returned key fields are checked, with
explicit degradation on mismatch; this does not establish interface lifetime.
Rows reuse the original query result and query window, including native failures.
Missing keys, family mismatch and the key budget leave an explicit unattempted
row query. Native query failures never erase the route. The summary separates
unique successful/failed native queries, uninterpreted/mismatched successful
results, cached row reuses and unattempted rows, including queried but undelivered
rows. These counts are not lost events. Missing native API support is unsupported
per lookup; an all-failed aggregate summary remains unavailable.

The native query uses a fixed initialized MIB_IPINTERFACE_ROW with no dynamic
native table allocation. All defined management fields are preserved: metric,
network-layer MTU, 14 raw BOOLEAN flags including forwarding/weak-host/default
route posture, router/link-local behavior, zone indices, prefix length, DAD and
reachability/retransmit/discovery/advertisement fields and transmit/receive
offload bits. Reserved fields remain explicitly reserved raw values. Unknown
enum values and noncanonical flags are uninterpreted/degraded; setting-only
Unchanged behavior sentinels are labeled without treating them as current
behavior. Invalid site-prefix length remains raw/degraded. Timers and flags
retain their applicability caveats, with no inferred effective packet path.
state.route_ip_interface publishes the manifest-bound summary with this narrow
route-associated scope. No interface policy or route is changed.

Native semantics: [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2),
[GetIpInterfaceEntry](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry),
[IP interface fields](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row),
[route row fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipforward-row2),
[reserved compartment getter](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getcurrentthreadcompartmentid),
[route origins](https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_route_origin)
and [route protocols](https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_route_protocol).
