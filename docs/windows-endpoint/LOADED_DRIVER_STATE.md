# Loaded-driver state and visibility

SCM registrations and loaded modules are separate observations. An independent
worker calls K32EnumDeviceDrivers for at most 4,096 native address slots, then
queries names/paths for non-null addresses. Full pointer-width values are decimal
strings. Later address lookups can race unload/address reuse; module, file and
service instance references remain null. Paths/names are raw text without file
opening, signature/hash/PE interpretation, path expansion or service matching.
Snapshots are non-atomic and inventory_complete remains false.

Microsoft documents that Windows 11 24H2 can report success with all NULL
addresses when SeDebugPrivilege is not enabled. The collector retains all
reported slots and classifies a nonempty NULL-only array as blind. Mixed or
non-null results remain degraded. Native zero returned slots do not establish an
empty complete census. The cause of NULL addresses is not asserted from the
array alone. This collector performs no privilege adjustment; native tests
compare owned-token privilege information before and after collection.

Native size overflow/misalignment and API failure retain explicit unavailable
status, source/error and query windows. NULL slots do not trigger name lookups;
their unattempted count is in objects, not events or native calls. Name queries
use 32,768-character buffers and preserve lossless text or original initialized
buffer bytes on possible truncation. Pages hold at most 256 entries and 512 KiB
encoded entry data; consumer and byte refusals cannot count uncommitted rows as
delivered. Queried but undelivered name failures remain scoped as query attempts.

Canonical begin, ordered pages and an exact-ID manifest commit through the
journal before stdout. Stable IDs/bytes retry on admission failure. Five-minute
refresh follows a committed manifest, with independent record-bound query
status, pending admission and commit-failure health. Abrupt incomplete captures
are retained without being called complete; persistent capture resumption and
reconciliation remain pending. Host/process/SCM workers continue when this API is
blind. Kernel signing/HLK/PPL/ELAM qualification does not gate this user-mode work.

Non-null native paths/addresses have not been qualified on this machine. Native
name/buffer fault injection, unload/address-reuse races, service/file/loaded-module
identity, signer and code-integrity evidence, continuous kernel image lifecycle,
privilege-qualified collection, heterogeneous OS/architecture execution,
deadlines/fairness/resource/soak qualification and Manager capture discovery/
assembly/Console remain open. Immutable record readback and Detection domain
retention support the new data without guessed process attribution.

References: [EnumDeviceDrivers](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers),
[driver file names](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getdevicedriverfilenamew).
