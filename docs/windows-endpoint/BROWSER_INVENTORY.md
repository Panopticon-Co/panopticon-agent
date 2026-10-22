# Windows browser extension metadata inventory

`collect_browser_inventory_pages(consumer, limits, cancelled)` is a read-only,
bounded collector for extension metadata. It scans the current process user's
native known folders and, when permitted, direct profile-directory candidates
under the configured Windows profiles directory. It emits normal
`NativeInventoryLimits` pages using
`browser_inventory_state_version` and the `browser_extension_inventory`
source. The caller must consume each page synchronously; returning `false`
stops collection.

For the current process identity, source roots come from
`SHGetKnownFolderPath` for Local AppData and Roaming AppData. The collector
checks Chrome, Edge and Chromium `User Data` folders under Local AppData and
Firefox `Profiles` under Roaming AppData. It additionally calls
`GetProfilesDirectoryW` and examines at most `user_profile_candidates` direct,
non-reparse directory entries, skipping conventional built-in names and the
current profile when its final path can be resolved. For other candidates it
checks only conventional relative locations for Chrome, Edge, Chromium, and
Firefox. A directory name is not mapped to a Windows account or SID, and the
process token remains the only authority used to read metadata. Access and
enumeration failures remain explicit refusals; the collector does not load user
hives, enable privileges, or bypass ACLs. An absent known-folder-derived
browser root or extension index is represented as a healthy absent source.

The profile scan is intentionally a candidate discovery mechanism, not an
all-user inventory. It cannot discover relocated browser data roots, nonstandard
installations, profiles outside the configured profiles directory, or data
denied to the current process identity. Candidate ordering is lexical after a
bounded native enumeration; reaching the bound reports omissions and degrades
coverage. Current-profile deduplication can be unavailable, in which case a
duplicate candidate may be observed and is reported.

Production pages omit raw profile and metadata paths. They carry random
per-capture salted SHA-256 path pseudonyms to correlate records within that
capture; these tokens are not stable between captures. If the system RNG is
unavailable, paths are still omitted and tokens are null. Other metadata such
as extension identifiers, names, permissions, file identities, and hashes is
still retained as described below and may be sensitive.

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
or running, identify all browser products, map profile candidates to accounts,
or claim all-user or full coverage. Firefox records do not have a separate
per-extension manifest hash:
each row carries the SHA-256 and native file evidence for the shared
`extensions.json` index from which its fields were selected.

## Integration

`src/state/browser_inventory.cpp` is registered in `officer-core`; the
independent runtime worker commits canonical pages/manifests and capture
freshness. The discovery summary and coverage limits are durable in the source
manifest. No build, test, or runtime validation was run for this wave; those
checks remain part of final integration.

Integration status: independent runtime worker, canonical durable pages/manifests and capture freshness are wired. This profile-discovery wave has not been built, tested, or run; validation is deferred to final integration.
