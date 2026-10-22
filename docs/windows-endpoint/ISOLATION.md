# Windows host isolation

Host isolation uses the Windows Filtering Platform through a non-dynamic engine session. The v2 policy creates default block filters at ALE authorization connect and receive/accept for IPv4 and IPv6 in one WFP transaction. This is connection-authorization filtering; it does not claim packet-layer or loopback coverage.

When configured, the sole outbound management exception must be one numeric IPv4 or IPv6 literal and a nonzero TCP destination port. Two conjunctive conditions bind the remote address and port at the matching IPv4 or IPv6 connect layer. DNS names are rejected because resolving a hostname to one transient address would give ambiguous release connectivity. No inbound Manager-address permit is created; inbound connection authorization remains blocked.

Applying a changed policy removes and recreates this agent's deterministic v2 filter keys in one transaction, so repeated commands do not retain stale Manager address/port conditions. The migration transaction also removes the previous v1 keys, whose Manager exception was address-wide and included a broad inbound exception. A failed add or cleanup aborts the transaction. Release deletes v2 filters and removes both v2 and legacy sublayers/filters in a transaction; repeated release tolerates absent filters.

This improves implemented IPv6 coverage, exception scope, atomic policy replacement, upgrade cleanup and key-collision refusal. This source increment has not been built and has no runtime enforcement verification. It is not qualified against existing third-party WFP providers, BFE restart/reboot, all NICs/compartments, DHCP/DNS/management survival, concurrent configuration, tampering or rollback failure. Filters are non-dynamic so they outlive this agent process, but are not configured with WFP persistent-across-reboot flags. A signed offline recovery path and reboot policy remain open; do not claim reboot persistence. Local firewall settings may still affect combined behavior.

## WFP key ownership checks

Before replacement or release, the endpoint now queries each deterministic
filter key and only deletes it when its `subLayerKey` matches the expected
Panopticon v2 sublayer. A filter key found under another sublayer aborts the
transaction. Legacy cleanup applies the corresponding v1 sublayer check. A
filter-add `FWP_E_ALREADY_EXISTS` after reconciliation is a failure, not
success, and an existing v2 sublayer key is accepted only when its display
name and weight match. This prevents accidental key collisions and false
isolation-success reports. It does not provide cryptographic ownership against
a local administrator, and the WFP objects do not yet use a registered provider
identity. No build, unit test, or Windows enforcement validation was run for
this increment.
