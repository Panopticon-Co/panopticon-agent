# Firewall profile state

Caller-visible base rule properties are collected by a separate paged worker;
see [firewall rule inventory](FIREWALL_RULES.md). Profile snapshot collection flags
describe this profile collector only. Neither collector establishes complete
effective firewall enforcement.

An independent read-only worker emits `state / firewall_profile_state` initially
and on a nominal five-minute schedule. Each record retains the selected native
query results before exposing record-bound health and `state.firewall_profiles`
coverage. Journal refusal retries identical canonical bytes and record identity.
Other state workers continue independently; COM and journal query deadlines are
not qualified. The worker is stopped/joined during endpoint shutdown.

The collector initializes its own MTA COM reference, activates the local
registered `INetFwPolicy2` class and balances successful initialization, including
`S_FALSE`. Initialization failure preserves the exact HRESULT and marks the 20 scalar
and three exclusion getters unattempted. A successful activation without an interface is a separate
validation failure; it retains the successful HRESULT rather than manufacturing
a native error. COM server integrity is not attested. See
[COM initialization semantics](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex).

Two global getters retain the currently reported profile bitmask and local policy
modification state. The three domain/private/public profiles are queried
separately with masks 1/2/4, including inactive profiles. Six getters per profile
retain local enablement, inbound blocking, notification suppression, unicast
responses to multicast/broadcast suppression and default inbound/outbound actions.
Multiple currently reported profile bits are not collapsed into one profile and
are not joined to a persistent interface or assumed atomic with later getters.

Facts preserve the source method, requested profile, per-query uptime window,
unsigned decimal HRESULT bits and signed decimal getter output. Failure retains
null output/value and unavailable field state. Recognized `VARIANT_BOOL` values
are exactly 0/-1; unknown values remain raw with null interpretation. Actions 0/1
are block/allow; unknown enums, bitmask bits and invalid sentinels remain degraded.
Outputs start with invalid sentinels, but write provenance is not independently
verified. Nonzero successful getter HRESULTs remain observable and degraded.
Getter query counts are distinct from source telemetry loss.

`FirewallEnabled` is local enablement and can differ from effective policy because
of Group Policy. Modification state is a report about changes, not an attempt
to modify policy. No setter, rule addition/removal, privilege adjustment or policy
alteration is performed. See [the policy interface](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2),
[local enablement](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_firewallenabled)
and [modification-state definitions](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_modify_state).

Aggregate state is degraded when any getter succeeds and unavailable otherwise.
`inventory_complete`, `atomic_policy_snapshot`, `effective_packet_policy_verified`,
`rules_collected` remains false. `excluded_interfaces_collected` is true only when
all three exclusion getter outputs are successfully and completely decoded. False local
enablement is a successful observed value, not a failed query. Initialization and
partial property failures cannot become a claim that the firewall is disabled.
Full rule/filter inventory, remaining exclusion semantics/lifetime coverage, service-hardening policy, Group Policy
provenance/precedence, effective per-interface/network-context enforcement,
third-party firewall coexistence, changes and reconciliation remain required.
This work supplements existing WFP response actions without treating isolation
filters as a complete firewall-policy inventory.

Native tests check independent getter failure and exact HRESULT bits, combined
active-profile masks versus separate query masks, unknown/sentinel values,
noncanonical booleans, nonzero successful HRESULTs and actual read-only native
collection. An owned STA apartment checks incompatible MTA initialization and
retention of the caller's apartment. Manager tests validate actual native records
against published contracts and preserve the original through duplicates,
immutable readback and Detection transformation with no manufactured actor.
Runtime tests verify matching committed state/health after owned abrupt exit,
including unread stdout/stderr with the eight implemented state domains.

Remaining qualification includes activation/service/permission faults, effective
packet validation, deadlines/cancellation and shutdown, CPU/RSS/latency under
storm, privacy/policy, analyst investigation integration, OS/ARM64/security
configuration matrix and soak. The full endpoint Definition of Done remains open.

Version 1.1 adds three independent `get_ExcludedInterfaces` calls, with separate
success/failure/incomplete/unattempted counts and per-profile coverage. Exact
HRESULTs, query windows, returned VARTYPEs and native array metadata remain
observable. A failed query is not an empty list. Recognized typed empty arrays
are empty reports; `VT_EMPTY`, `VT_NULL`, BYREF and unrecognized shapes remain
uninterpreted. On this development host all three successful getters returned
`VT_EMPTY`; all three stay degraded with null list interpretation. We do not
assume a specific empty-VARIANT convention or claim no exclusions from these
samples. See [the exclusion getter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_excludedinterfaces).

Borrowed trusted COM arrays accept one-dimensional BSTR or VARIANT arrays with
matching native element type/size. Native lower/upper indices are preserved;
item count is bounded to 128 before data access. Strings are bounded to 4,096
UTF16 units/8,192 BSTR bytes each and 16,384 copied bytes per profile. Oversized
strings leave explicit unknown-name entries, without erasing the reported row.
Duplicate names and embedded NULs are retained; names never become verified
interface references. Invalid UTF16 retains exact little-endian hex bytes and
conversion errors. Odd-length BSTRs retain every byte with degraded validation,
including the trailing byte that `SysStringLen` alone would omit. Selected
nontext scalar variants retain raw decimals; unsupported values retain their
type and explicit uninterpreted state, without coercion, recursion or BYREF
pointer dereference.

Arrays are borrowed under bounded native data access and unlocked before their
owning getter VARIANT is cleared. Access/unaccess and cleanup HRESULTs remain
separate from the original getter HRESULT. Native COM allocations and allocator
RSS are not bounded by copied-data limits. These are trusted local COM objects,
not a parser for arbitrary remote memory; corrupted pointer safety, allocation,
cleanup/deadline faults and server integrity remain unqualified. See
[SafeArrayAccessData](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayaccessdata)
and [SafeArrayGetVartype](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearraygetvartype).

Additional owned-array tests cover embedded NULs, invalid UTF16, odd byte lengths,
negative lower bounds, duplicate names, scalar/BYREF variants, typed empty arrays,
large item/string/aggregate bounds, multiple dimensions and borrowed-array lock
release. No test changes the host's firewall exclusions or policy. Nonempty native
exclusion lists, empty-VARIANT semantics, verified interface mapping and remaining
firewall/full endpoint qualification remain open.
