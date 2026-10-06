# Native socket state

An independent worker queries GetExtendedTcpTable with OWNER_PID_ALL and
GetExtendedUdpTable with OWNER_PID for IPv4 and IPv6. Each table has its own
native return code, query window, buffer/row limits and coverage state. These
APIs report endpoints available to the caller; their success does not prove
complete host visibility. Four queries and later durable page admission are
non-atomic. Inventory completeness remains false, and aggregate socket coverage
remains degraded when any table reports rows, including zero rows.

Rows preserve exact native structure bytes, full DWORD owner PID, TCP state,
ports and IPv6 scope IDs. Addresses retain network bytes. Port decoding is
explicitly limited to the low 16 network-order bits; upper bits remain in the
raw DWORD. Unknown TCP states retain their raw values and null symbols, degrading
the table. The qualification host returned raw TCP state 0; its meaning is not
asserted. Listening TCP rows retain raw remote fields but explicitly mark them
as meaningless for LISTEN. UDP rows have null remote peers and TCP state.
Reported owner PIDs never become process-instance or socket-instance references;
both references remain null. Socket-to-process verification and native lifetime
identity are separate outstanding capabilities.

Each query starts with a zero-initialized 64 KiB native buffer, allows at most
three calls and refuses requests above 8 MiB. Successful reported size bounds
the decode span; the API describes this size as estimated, so it is not labeled
as a proven count of initialized native bytes. SDK table offsets and fixed row
sizes guard count arithmetic before any row reads. At most 65,536 rows per
table reach decoding. Failed calls retain their returned Win32 code directly,
with explicit resize, retry and buffer bounds. Unsupported status requires
ERROR_NOT_SUPPORTED. Other failures retain unavailable/null results.

Pages contain at most 256 entries and 512 KiB encoded entry data, with a 4,096
page bound. Attempted page count is distinct from accepted entries. Per-table
rows delivered to the page builder, rows in accepted pages, reported native
count and completeness of page acceptance are separate facts. Failed consumers
cannot count refused rows as accepted. Further native tables are not queried
after consumer refusal and report that limitation explicitly. No query count
or unattempted native row set is mislabeled as a count of lost network events.

The production consumer commits canonical socket_inventory_begin, ordered
socket_inventory_page records and an exact-ID socket_inventory manifest through
the encrypted journal before stdout. Admission failure retries stable bytes and
IDs; the worker does not advance to another capture until the manifest commits.
Refresh follows a committed capture at five minutes. Health carries the exact
committed manifest ID and query status, pending admission, committed pages and
commit failures. state.socket_inventory and state.socket_table.tcp4/tcp6/udp4/udp6
have explicit scopes. Healthy table status means this bounded native query and
page admission completed with recognized values, not continuous network coverage.
Event-source startup failure does not stop this state worker.

Native tests create only owned loopback TCP listeners and UDP endpoints in both
families. They check all four tables, raw full-width values, malformed buffers,
unknown states, exact error retention, resize/allocation bounds and partial-page
refusal. Manager tests validate the published canonical schema, exact accepted
wire-body readback/digest and Detection preservation without guessed actors.
An owned-process abrupt-exit/reopen harness verifies exact durable pages,
manifest, per-table counts and manifest-bound coverage health.

Continuous flows/connect attempts/failures/byte counts, verified actor and socket
lifecycle, reconciliation, routes/interfaces/proxy, DNS, firewall posture,
privileged visibility, API deadlines, freshness and stale-capture policy,
exception/crash intent, durable gap accounting, OS/ARM64/resource/storm/soak
qualification and analyst capture assembly remain open. This increment does
not qualify full network EDR coverage or the endpoint Definition of Done.

Native API semantics: [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
[GetExtendedUdpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable),
[MIB_TCPROW_OWNER_PID](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid).
