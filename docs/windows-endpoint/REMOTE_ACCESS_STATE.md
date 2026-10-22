# Local SMB server state

The agent now periodically captures two caller-visible views from the local
Windows SMB server APIs: `NetSessionEnum` level 10 sessions and `NetFileEnum`
level 3 open-file records. The collector uses explicit page limits, validates
the returned row arrays and every string pointer/terminator against the native
buffer, bounds copied strings and records native query failures and incomplete
partitions. The existing native state worker writes a durable begin record,
pages and a manifest, then exposes independent freshness and coverage.

This is a read-only state snapshot. It does not read file contents, perform
network connections, enumerate outbound SMB clients, identify an actor process,
or prove the authentication method. Session `username` and client names are
native API reports only; returned open-file paths are not reopened or verified
as file identities. The session and file queries are separate and non-atomic.
Enumeration is limited to what the current caller can see, so permission
refusals and host role/API availability can leave the result unavailable or
partial. The application bounds copied data and checks budgets between native
calls; NetAPI allocations and call duration are not hard-bounded by this code.

No build, component test or Windows runtime validation was performed for this
addition. Treat it as implemented source, not a verified endpoint capability.
