# Defender preferences inventory

The native collector reads selected caller-visible values from
`Root\Microsoft\Windows\Defender:MSFT_MpPreference` using WMI `ConnectServer`,
`ExecQuery`, `IEnumWbemClassObject::Next`, and `IWbemClassObject::Get`. It does not
call `ExecMethod`, write registry values, change Defender configuration, enable
privileges, bypass controls, or use the network.

The captured allowlist covers ASR rule IDs and action values; controlled folder
access mode, protected folders, and allowed applications; path, extension, and
process exclusions; real-time, behavior, IOAV, script, network, PUA, cloud,
sample submission, scan, and signature update preferences. Unknown provider
properties are not enumerated: add them deliberately to the allowlist. A failed
or absent getter is retained as a property-level result. Each value carries its
VARIANT type and raw scalar carrier; supported one-dimensional arrays retain
their element type, bounds, and ordered values. Unsupported types remain
uninterpreted instead of being coerced.

The WQL query explicitly selects only the allowlisted property columns rather
than requesting every property from the WMI class. `VT_BYREF`, vector, and
unsupported flag combinations are rejected without dereferencing their union
storage. Malformed or odd-length BSTR values are retained as bounded UTF-16LE
hex with a validation error; floating-point and date values retain their raw
bit pattern and are not normalized. Safe-array element read errors retain the
specific HRESULT. If `Next` returns a timeout together with an object, that row
is retained with its source HRESULT and partial-timeout status.

ASR IDs and actions are reported separately. The collector does not join them
into rule/action pairs. Likewise, controlled-folder and exclusion arrays are
reported as provider values, not normalized filesystem paths or proof that a
path is active. A configured or reported preference does not establish effective
enforcement, policy authority, tamper protection, provider integrity, or
successful protection. The output explicitly leaves protection and policy
authority unverified.

## Page API

Include `panopticon/officer/state/defender_preferences.hpp` and call
`collect_defender_preferences_pages(consumer, limits, cancelled)`. The consumer
receives `defender_preferences_page_v1` JSON pages, each containing one
`MSFT_MpPreference` object row per provider result. The returned
`defender_preferences_inventory_v1` JSON is the manifest: it reports pages,
delivered rows, bounds, cancellation, timeout, provider query errors, and
whether WMI enumeration reached its end. Callers should persist the pages and
manifest as separate durable records and must not claim completeness unless the
manifest says `enumeration_complete`; `inventory_complete` remains false because
the collector only selects a bounded subset of provider properties.

Bounds cover application copies, field bytes, rows, pages, encoded page size,
and a soft elapsed-time budget checked between native calls. `Next` uses a
finite one-second timeout; `WBEM_S_TIMEDOUT` is reported as timeout, never as
end-of-enumeration. A timed-out call that also returns an object retains that
row with partial source status. Cancellation is also checked between calls. COM/RPC calls,
the WMI provider, and allocations performed inside native APIs cannot be given a
hard time or memory bound by this collector. Snapshot reads are non-atomic and
do not attest the lifetime of the provider or machine state.

The output can contain sensitive local security configuration, application
paths, exclusions, and protected-folder names. Consumers should apply the same
access controls, retention, and redaction policy used for other endpoint
configuration inventory.

Integration status: independent runtime worker, canonical durable pages/manifests and security-product capture freshness are wired. The combined Windows executable compiles; no new runtime test was run for this source.
