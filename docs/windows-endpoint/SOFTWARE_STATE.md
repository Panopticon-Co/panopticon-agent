# Native software registration state

Two independent read-only workers capture MSI product registrations and selected
uninstall-registry values. Each uses durable begin/pages/ordered manifests,
immutable journal admission retries and record-bound freshness. Coverage remains
partial. Registration metadata does not prove installed files, software execution,
an executable version or a verified signer.

MSI enumeration uses separate machine, all-user managed and all-user unmanaged
contexts. Machine queries use a null SID; all-user queries request S-1-1-0.
Permission failures do not suppress other contexts. An index advances only after
successful enumeration; output from a refused/oversized call is not interpreted.
Property getters are subsequent, non-atomic reads, including reported name,
version, publisher, install location/date, state, assignment and language. MSI
advertised registrations can appear; the API omits advertised-only unmanaged
products belonging to other users. No repair/configuration/install API is called.
See [Microsoft MSI enumeration](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msienumproductsexw)
and [property querying](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msigetproductinfoexw).

Registry inventory traverses HKLM, current caller and loaded valid-SID HKU
uninstall keys in explicit 32/64 views. Duplicate/shared-view registrations stay
separate; there is no inferred cross-source product identity. It queries only
selected display/version/publisher/location/date/size/installer/component/type
properties, retaining exact typed bytes and malformed representation. Missing
values and absent partitions are distinct from access/query failures.
Uninstall strings are neither collected nor executed. No environment expansion,
profile hive mounting, installed-file traversal or signature verification occurs.
Registry state is self-reported metadata; reported publisher is not signer proof.

Common limits bound application field copies, entries, pages and encoded page
bytes, with observable refusals/cancellation and a soft elapsed-time budget.
Native APIs have no guaranteed hard deadline/allocation cap. Churn can reorder
indexed registrations; enumeration completion is not atomic inventory coverage.
Incomplete capture beginnings/pages remain evidence on interruption.

Remaining surface: MSIX/AppX and provisioned packages, portable/software file
inventory, unloaded user profiles, patch/component details, exact version/signer
verification, relationships, change watchers/reconciliation, privacy policy,
privileged/OS/VM/churn/fault/resource/reboot/soak qualification. Z is partial.

Native component tests include an owned HKCU registration and malformed UTF-16
value, page bounds, actor-null semantics, admission refusal and cancellation.
The owned fixture never executes software and removes only its uniquely created
key. Freshness tests cover independent MSI refusal and stale domain blindness.
Runtime evidence is recorded in VALIDATION.md as runs complete; a prepared guest
script or successful host test does not qualify the VM.
