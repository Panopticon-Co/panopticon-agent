# SCM service state changes

`ServiceStateChangeSource` adds a Windows-native, standalone source for
Service Control Manager status transitions. It uses
`NotifyServiceStatusChangeW` on per-service handles. It also performs a bounded
SCM enumeration on startup and periodically to discover service names that did
not exist at the preceding reconciliation. The current service inventory
remains the source for broader service configuration and DACL evidence.

`state` in `status()` describes source lifecycle. The separate
`coverage_state` never claims full service-change coverage: it is degraded by
default while running because reconciliation has gaps and actor attribution is
absent, and blind when queue drops, subscription failures, enumeration errors,
truncation, or watch-capacity skips are observed.

## Contract and evidence scope

Each callback record preserves the SCM service name, callback status code,
trigger mask, returned `SERVICE_STATUS_PROCESS` scalar values, callback
sequence, and local receipt time in FILETIME units. A reported service PID is
not a verified process instance; the source makes no actor attribution claim.
The receipt timestamp is sampled inside the callback and is not the exact
transition time. Driver services appear in the SCM enumeration, but this API
does not observe kernel driver load/unload events, image identity, or code
integrity. Configuration changes are not status changes and are outside this
source's coverage.

## Resource and failure bounds

Default bounds are 2,048 queued callback records, 4,096 service subscriptions,
a 4 MiB native enumeration buffer, and a 30-second reconciliation interval.
Limits are validated at construction. SCM enumeration is not atomic and may
return `ERROR_MORE_DATA`; the source subscribes to entries present in the
returned buffer and records truncation. Service handles are retained for the
source lifetime, including services that disappear, so repeated service-name
churn cannot cause unbounded re-subscription or stale-handle reuse. When the
watch limit is reached, later names remain uncovered and the subscription
failure counter is incremented.

Callbacks only copy the bounded service name and fixed status structure into a
bounded queue, then signal a dedicated worker to re-arm the one-shot
notification after the callback has returned. Queue/allocation loss
increments a counter and advances a source-local sequence, exposing gaps. A
failed re-arm increments a subscription failure counter; the affected service
may then be blind. Deleted service handles are retained for lifetime safety,
so a service recreated under the same name is not re-subscribed by this source
instance; the subscription-failure/coverage state must remain degraded and a
source restart is currently needed. SCM provides no
global event cursor or provider-side loss counter through this API. Periodic
enumeration discovers names but is not a substitute for missed intermediate
status transitions.

The notification function is resolved from System32 at runtime. If absent,
the source reports `unsupported`; SCM access denial and other initialization
errors report `unavailable`. `stop()` wakes the reconciliation thread,
closes service handles to cancel pending notifications, waits for in-flight
callbacks, and leaves already queued records available to the caller.

## Runtime integration and qualification still required

The source is registered in `officer-collectors` and started by a dedicated
worker after service inventory. The worker commits a start record, a record per
reconciliation generation, native notifications, and counter-delta gaps via
`EndpointRecordFactory` and the endpoint journal. It holds at most one
immutable refused record and retries it before draining more source data. It
projects source health and durable-acceptance state, stops subscriptions before
join, and drains one queued item at a time during shutdown. The source begin
record ID is used as a capture ID for subsequent records. Integration is at
source level only and does not prove successful compilation or journal/runtime
behavior.

Integrators must not report healthy service-change coverage when enumeration
truncates, access is refused, watch capacity is exceeded, any subscription
fails, callback queue drops occur, or durable acceptance is pending.

This code has not been built, component-tested, or exercised on a Windows VM.
The callback re-arm and handle-close lifecycle, service churn, large SCM
databases, callback cancellation, Windows Server behavior, and durable loss
accounting remain qualification work. Shutdown commit refusal and SCM service
deletion/recreation need runtime fault/churn tests. Until evidence exists,
regard the collector and integration as implemented but unverified and the
service domain as partial.