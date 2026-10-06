# Independent IP interface census

An independent worker queries GetIpInterfaceTable separately for IPv4 and IPv6.
Enumeration does not depend on routes, processes or event-source availability.
The route-associated GetIpInterfaceEntry evidence remains a different, later
observation; no persistent entity join or equality of capture times is asserted.
GetIpInterfaceTable enumerates IP management rows in the caller context. This
does not establish complete link-layer/physical adapter, namespace/compartment
or continuous interface visibility. inventory_complete,
all_compartments_complete and interface_lifetimes_verified remain false.

Rows reuse the shared bounded SDK decoder for all defined MIB_IPINTERFACE_ROW
fields: family, full-width LUID/index, metric/MTU, fourteen raw BOOLEAN flags,
router/link-local behavior, zone indices, site-prefix length, DAD and
reachability/retransmit/discovery/advertisement fields, offload capability bits
and explicitly reserved raw values. Source/scope distinguish an independent
table row from a later single-interface lookup. Invalid prefixes, unknown
families/behaviors, setting-only Unchanged sentinels and noncanonical flags
remain raw/degraded rather than becoming defaults. Timers and flags retain
applicability caveats. Interface-instance references remain null. No effective
packet path or actor is inferred, and no interface/route policy is changed.

The OS owns each native table allocation and provides count plus SDK-aligned
rows without allocation byte length. RAII calls FreeMibTable; only bounded
native row copies survive into page production. At most 65,536 rows and 8 MiB
copied row bytes per family are admitted; whichever bound applies first wins.
Reported count is checked before reads/copying. The OS allocation has already
occurred, so native_allocation_bounded is explicitly false and the native
allocation extent remains trusted rather than independently proven. Original
padding/inactive memory bytes are not serialized.

Native errors retain their exact returned codes. ERROR_NOT_SUPPORTED maps to
unsupported for that family; other errors remain unavailable/null, including
ERROR_NOT_FOUND without a claim of complete empty census. Success with a null
table is a validation refusal while native_error_code stays 0; validation must
never invent a native API failure. Bad copied-row count/size and excessive
counts are separate validation/bound results. The same distinction is now
preserved by the route table collector.

Pages are limited to 256 entries, 512 KiB encoded entry data and 4,096 pages.
Queried/decoded counts and accepted rows are distinct. A refused page never
counts as accepted; subsequent family queries report explicit unattempted state.
Canonical ip_interface_inventory_begin, ordered ip_interface_inventory_page
records and an exact-ID ip_interface_inventory manifest commit through the
encrypted journal before stdout. Stable bytes/IDs retry on admission failure.
Five-minute refresh follows a committed manifest, with independently published
manifest-bound query status, pending admission and commit/page counts.
state.ip_interface_inventory stays degraded/unavailable;
state.ip_interface_table.ipv4/ipv6 can report healthy only for their scoped
recognized native fields and complete reported-row page admission.

Native tests enumerate synthetic interfaces without any route source, enforce
SDK copy/count bounds, preserve native support/errors separately from validation,
and verify accepted-prefix accounting after page refusal. Actual read-only
collection generates canonical fixture records. Manager validates the published
schema and preserves original accepted bodies/digests; Detection receives
unchanged data with no actor. The owned-process crash/reopen harness verifies
exact pages, manifest, per-table counts and committed health independently of
route capture and event-source startup.

Continuous interface changes, reconciliation, verified lifetime and complete
compartment coverage, link-layer stack/physical adapter and effective-path
relationships, freshness, native allocation/deadlines/fault/crash/loss intent,
OS/ARM64/resource/storm/soak and analyst capture assembly remain open. This is
an implementation increment, not full network or endpoint qualification.

Native semantics: [GetIpInterfaceTable](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfacetable),
[IP interface fields](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row)
and [FreeMibTable](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable).
