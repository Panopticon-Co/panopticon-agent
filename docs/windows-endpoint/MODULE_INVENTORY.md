# Native process module inventory

The periodic `module_inventory` worker rotates through up to eight caller-visible
process candidates per five-minute capture, with a separate in-memory PID cursor.
It opens a process with query-limited and synchronization access, retains the
handle, obtains PID and creation FILETIME, and requires it to remain alive before
and after the PID-based Toolhelp module snapshot. PID zero is refused explicitly
because Toolhelp would otherwise interpret it as the current process. Missing
boot identity retains a native-unscoped process reference, never an exact entity.

`TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32` requests the loader's native and WOW64
module lists where the collector architecture permits. `ERROR_BAD_LENGTH` is
retried at most three times. Other native failures, including architecture and
access failures, remain exact Win32 refusal evidence. Collection does not enable
privileges, request VM read/write access or change a target.

Each process contributes at most 512 module descriptors. Rows retain the source
PID, base address, image length, bounded native module name/path, snapshot flags,
retry count and held process reference. Fixed strings preserve termination status
and malformed UTF-16 through the existing lossless native-text representation.
Names and paths are descriptor reports: there is no file-object identity, signer,
hash, module-instance identity, content or injection verdict. Loader snapshots
exclude datafile/manual mappings and do not establish continuous load/unload
visibility. Mapping addresses may be reused after the snapshot.

The worker uses the existing canonical begin/page/ordered-manifest capture path.
Each canonical record is retried unchanged until journal acceptance; the cursor
advances only after the manifest commits. The process cursor is volatile and
restarts at zero after endpoint restart; it is scheduling state, not a durable
event-source checkpoint. Crash-abandoned captures remain incomplete. Manifest
accounting counts modules only in consumer-accepted pages. Query failure,
per-process truncation, page refusal, cancellation and soft budget expiry are
reported separately. Application rows/pages/candidates are bounded; native
Toolhelp allocation/calls do not have hard memory or execution deadlines.

The worker starts unavailable, reports partial/degraded coverage after successful
metadata delivery, and exposes independent committed-capture freshness. Overdue
captures become blind. Zero module delivery remains unavailable. None of these
states establish full memory, image-load, process or injection coverage.

The accompanying native component executable covers its own image/base address,
held exact and unscoped process references, PID-zero refusal, module truncation,
consumer refusal, cancellation, invalid retry limits and stale-capture blindness.
Consult [the validation ledger](VALIDATION.md) for actual execution evidence and
remaining guest/runtime, protected-target, restart, OS and load qualifications.

Native reference: [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot).
