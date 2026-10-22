# Windows browser extension metadata inventory

`collect_browser_inventory_pages(consumer, limits, cancelled)` is a read-only,
current-caller collector for extension metadata under the caller's native known
folders. It emits normal `NativeInventoryLimits` pages using
`browser_inventory_state_version` and the `browser_extension_inventory`
source. The caller must consume each page synchronously; returning `false`
stops collection.

The source roots come from `SHGetKnownFolderPath` for Local AppData and Roaming
AppData. The collector checks Chrome, Edge and Chromium `User Data` folders
under Local AppData and Firefox `Profiles` under Roaming AppData. It does not
expand environment variables, scan other users or infer paths from process
configuration. An absent known-folder-derived browser root or extension index
is represented as a healthy absent source; access, enumeration and native API
errors remain unavailable refusals with their Win32 or HRESULT code.

For Chromium-family profiles it enumerates the fixed `Extensions/<id>/<version>/manifest.json`
layout. For Firefox it reads the profile's `extensions.json` metadata index.
Both sources are held open while reading. The implementation rejects reparse
directories and files, checks each opened object's final path remains below
the corresponding browser data root, and never follows a discovered reparse
entry. File rows include native file identity and timestamps when the OS query
succeeds, a SHA-256 of the exact bounded metadata bytes, and selected declared
metadata such as name, version, manifest version, permissions, and Firefox's
active/disabled fields. Those fields are browser-maintained declarations, not
independent proof of installation or runtime state.

Chromium `permissions` and `host_permissions` stay in separate arrays. Selected
metadata uses primitive type and byte limits; `manifest_version` is accepted
only as an integer from 1 through 3. Rows report omitted field and array
element counts, and metadata completeness is degraded when a bound or type
check omits values. File size and last-write time are observed before and after
each metadata read when the native queries succeed. A changed flag records
detected change; unchanged observations do not establish an atomic version.
The hash identifies the exact byte buffer read between those observations.

Limits cover pages and encoded output, profile candidates, directory
candidates, manifest candidates, the fixed traversal depth, bytes per metadata
file, JSON nesting, and selected string lengths. Cancellation and the soft
time budget are checked between native operations. Windows filesystem calls
and allocations inside the OS do not have a hard deadline or hard allocation
bound. Enumerations and file reads are non-atomic; a file can change after it
is observed.

For future inert fixtures, callers may populate
`BrowserInventoryLimits::owned_inert_fixture_roots`. Every entry must carry
the explicit `caller_owned_inert_fixture` flag, an absolute path, and one of
the supported browser labels. Supplying any fixture roots replaces known
folder discovery for that call; the result labels itself as fixture-only.
Callers are responsible for providing inert, caller-owned fixture trees.

The collector reads only extension metadata JSON. It does not inspect browser
executables, extension scripts/binaries, credentials, cookies, history, or
network state. It does not verify signatures, prove extensions are installed
or running, identify all browser products, enumerate all users, or claim full
coverage. Firefox records do not have a separate per-extension manifest hash:
each row carries the SHA-256 and native file evidence for the shared
`extensions.json` index from which its fields were selected.

## Integration

Add `src/state/browser_inventory.cpp` to `officer-core` in CMake and expose
`browser_inventory.hpp` to the Windows collector/dispatch layer. Call the
collector with the shared page consumer and propagate the collector's summary
as that source's coverage result. The implementation is intentionally not
registered in `main.cpp` or a shared capability ledger; those integration
changes are owned by the parent task.

Integration status: independent runtime worker, canonical durable pages/manifests and capture freshness are wired. The combined Windows executable compiles; no new runtime test was run for this source.
