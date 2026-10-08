# Device Guard and VBS provider capture

An independent five-minute worker queries the local WMI class
`Root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard`. It preserves ten selected
properties: instance path/identifier/version, VBS status, kernel and user-mode
code-integrity policy status, available/required security properties and
configured/running security-service arrays. Microsoft describes the provider in
its [memory integrity guidance](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).
The collector performs no host policy changes or enforcement methods.

Each getter retains its HRESULT, reported CIM/VARIANT type, native carrier,
capture clocks and quality. Scalar codes and array codes remain decimal strings;
the endpoint does not interpret them as independently verified protection.
Arrays retain order, signed carrier values, and arbitrary SAFEARRAY lower bounds.
Unknown enum values remain visible. Null, BYREF, wrong type/dimension, failed and
informational query results remain unavailable or degraded without coercion.
Successful property reads can be healthy while overall coverage remains degraded.

Bounds are eight rows, 64 elements per array, 32 KiB copied per row and 640 KiB
encoded entries. These are endpoint copy bounds, not WMI native allocation bounds.
ConnectServer uses its native maximum-wait flag, enumeration waits one second per
Next call, and collection remains non-atomic without a hard overall deadline.
Provider stalls may delay worker shutdown; fault and deadline qualification remain
open. Missing provider/privilege is preserved as unavailable, not interpreted as
disabled VBS, absent protection or platform-wide unsupported capability.

The immutable `device_guard_state` canonical record is retained until durable
journal acceptance. Failed acceptance retries the same pending record. Independent
health binds the exact committed body and record ID, exposes commit refusal and
in-progress collection, and marks stale captures blind through source freshness.
Current capture freshness does not establish current effective protection.

2026-10-07 evidence: fresh Debug/Release builds passed all 38 CTest entries
(24.98/22.07 s). SAFEARRAY fixtures cover signed carriers, nonzero lower bound,
unknown uint32 code, type mismatch, array bound, BYREF refusal, denied getter and
stale-source blindness. A real Windows-host native component query returned ten
readable properties. An owned 20-second Release runtime followed by abrupt exit
and two byte-identical journal readbacks recovered 11,643 canonical records;
Schema 1.0 validation and Manager body preservation passed for every original.
One Device Guard capture and 22 health bindings were verified against exact body,
record identity and capture/commit clock ordering. The repeatable verifier is
`tools/validate_device_guard.py`. Evidence is
`demo-run/device-guard/persistence-runtime-0caed55b684c49ef805d39476ed27a2f/device-guard-report.json`.

This is real Windows-host provider/runtime recovery evidence. Effective VBS/HVCI,
Credential Guard or WDAC enforcement, attestation, policy authority, change
telemetry, hostile provider handling, OS/security configuration compatibility,
hypervisor identity and VM/WSL/container inventory remain unverified or missing.
Subsequent dedicated-guest execution verifies one durable provider capture and
22 exact committed health bindings after abrupt exit/reopen, plus the native
component executable with exit zero. See [validation](VALIDATION.md). This does
not verify effective enforcement, the OS/security matrix or full X/Y qualification.
