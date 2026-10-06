# Diagnostic output and durable acceptance

The production main loop accepts canonical observations, state pages, gaps and
response evidence into the journal before submitting their stdout display copy.
Structured health is committed before submitting its stderr display copy. Main
runtime diagnostics and response-cycle messages use the stderr worker. CLI and
early initialization errors still use direct streams; other libraries' logging
and startup behavior require separate qualification.

Each writer duplicates its borrowed handle and owns one synchronous native write
thread. Submission uses a preallocated ring and a short admission mutex, without
waiting for display capacity or performing native I/O. Stdout has 1,024 owned
lines/8 MiB; stderr has 256 lines/4 MiB; both limit input lines to 1 MiB. Queued
and in-flight item objects and string capacities remain charged. Fixed ring
storage, threads, allocator overhead and temporary admission copies are excluded
from this charge. Allocation and mutex scheduling prevent a hard latency/RSS
claim. Initial state/ring allocation can still fail endpoint initialization.

Health records include `pipeline.diagnostic_stdout` and `diagnostic_stderr`, with
distinct capability entries. Counters are decimal strings and reconcile accepted
volatile lines into completed native writes, failed native writes, abandoned
unattempted lines and current ownership. Refused/exception-refused display copies
are separate. These counters reset on restart, and are not telemetry loss
accounting. A successful native write proves neither reader consumption nor
durability. Earlier successful write chunks and bytes reported on a failed call
remain separate; a failed call's reported bytes are not credited as completion.
Validation failures do not manufacture native error codes. Worker-start failures
retain the C++ system-error category/value separately from Win32 write errors.

Close stops admission and allows 100 ms to drain, then abandons queued lines and
retries cancellation of the owned synchronous writer for up to 1,000 ms. Native
cancellation can finish normally, fail, or remain pending; it is not a guaranteed
completion receipt. See Microsoft's [CancelSynchronousIo documentation](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelsynchronousio).
If completion misses this deadline, health exposes the failure and the worker
retains shared ownership of its handle and buffers until I/O returns. It is not
terminated and has no dangling references to the outer object. This fallback is
not proof of eventual release or a whole-agent shutdown deadline. Close has one
owner; concurrent close calls are unsupported. The final main-loop health record
retains writer shutdown accounting before stopping delivery.

Native tests use owned unread anonymous pipes to prove in-flight capacity,
prompt refusal, native cancellation, disposition accounting and bounded close;
they also check exact embedded-NUL/newline framing, borrowed handle preservation,
invalid handles and the actual closed-reader Win32 error. The owned runtime test
leaves both agent output pipes unread, terminates only its own process and then
opens only its stopped spool. It verifies all seven implemented state domains,
durable health and bounded/reconciled diagnostic ownership. The normal file-output
runtime check still verifies exact retained pages, manifests and health.

Remaining qualification includes startup/library logging, worker-start resource
faults, cancellation deadline fallback, atypical/overlapped handles, console/file
device faults, allocator contention, OS/ARM64 compatibility, sustained load and
soak. The full 40-domain matrix and endpoint Definition of Done remain open.
