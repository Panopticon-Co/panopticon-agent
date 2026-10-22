# Windows network state change notifications

`NetworkStateChangeSource` is an isolated native collector for Windows IP
Helper notifications covering IP interface rows, unicast address rows, and
route rows. It uses `NotifyIpInterfaceChange`,
`NotifyUnicastIpAddressChange`, and `NotifyRouteChange2`. The source describes
local network configuration changes; it does not observe network connections,
packet flows, DNS activity, or the process that caused a change.

## Startup and reconciliation

The collector registers all three notifications with initial notification
enabled before querying the three tables. It retains callback rows while the
queries run and publishes the bounded initial table snapshots before callback
records. Each snapshot carries start and finish UTC receipt times and is marked
non-atomic. Notifications carry their own monotonically increasing local
sequence and callback receipt time. A change during enumeration can therefore
appear both in the snapshot and in the notification stream; consumers should
accept this possible duplicate and use the sequence to order notifications.
The timestamp is the time this process sampled the system clock at callback
entry, not a kernel change time.

Each snapshot has a row limit for rows retained and decoded by this collector,
and reports native error, captured count, reported count, truncation, and
completeness. Windows allocates each complete native table before returning it;
this collector cannot bound that API-owned allocation. The snapshots are independent;
they do not claim a simultaneous view of all three tables. Registration failure
rolls back any successful registrations and makes `start()` return the native
error. A successful registration followed by an unavailable table query is
reported on that table's snapshot without disabling the other streams.

## Callback, queue, and stop behavior

Callbacks capture a native FILETIME and copy the native row bytes into a
preallocated fixed-capacity ring before returning; they do no string formatting,
dynamic allocation, table lookup, or serialization. The queue allocation is
bounded by the constructor's validated 65,536-record maximum. Windows documents
that callback rows may be incomplete. The record marks that scope and preserves
the native notification type and copied row fields; it never treats a missing
field as proof of deletion. Initial notifications have a null row and are
retained as such. UTC formatting and JSON construction occur only when the
worker drains the queue.

The callback queue is bounded (default 4,096 entries; configurable up to
65,536). Every callback invocation that reaches the source advances the local
sequence, including invocations refused because the queue is full or shutdown
has begun. `status()` reports accepted, queue-full, stop-refused, and callback
copy/queue error counts plus the sequence high-water mark. Rejected calls
therefore create visible sequence gaps. IP Helper does not expose provider-side
loss counters here, so the source cannot report loss that happened before a
callback reached this process. Callers must drain promptly and persist records
if they need continuity across process termination; this component has no
durable queue.

Because the native callback rows are partial, change records expose only their
documented lookup identity: interface family/LUID/index; address/family/LUID/
index; or route destination prefix/next hop/interface LUID/index. A later
complete-row lookup is intentionally not performed in the callback and may no
longer succeed by the time a worker attempts it.

`stop()` returns the first native cancellation error, deregisters each
subscription, waits for callbacks already in flight, and leaves buffered
records available to `drain()`. A callback rejected during stop is counted. A
failed cancellation leaves status at `stop_failed`; destruction preserves its
callback context to avoid a use-after-free if Windows continues to call it. A
stopped source cannot be restarted, preserving one source sequence lifetime
per instance. The caller remains responsible for scheduling drains and
observing status.

## Provenance and scope

Each change record carries `source=Windows IP Helper notification API`, the
native notification kind, a decimal local sequence, and a UTC callback receipt
time. Address and route data retain only fields reported in the native row.
Interface LUIDs and indices are reported identifiers, not durable interface
identity. Process attribution is always unavailable from this source. No
effective route selection, socket ownership, flow, packet, or DNS claim is
made.

The source is registered in CMake and wired into the endpoint runtime. Startup
snapshots, their capture manifest, notification records, and explicit callback
loss gaps are routed through the endpoint record factory and durable journal.
The worker retains one serialized record when journal admission is refused and
does not drain further notifications until that record is accepted. Shutdown
deregisters the source before draining callbacks already accepted by the API.
This wiring has not yet been built or executed on Windows. Queue-fault,
restart/replay, schema, journal-refusal, notification churn, and OS qualification
remain pending; no real-Windows behavior is claimed.
