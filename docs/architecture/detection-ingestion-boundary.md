# Panopticon ingestion and detection boundary

Officer produces observations. It does not decide whether an observation is
malicious.

The future backend flow should be:

```text
Officer batch
  -> authenticate agent
  -> validate schema version and limits
  -> assign ingestion metadata
  -> append immutable observations
  -> reconcile cross-source process identity
  -> run stateless and stateful rules
  -> correlate related entities and events
  -> create or update alerts
  -> expose evidence to the analyst console
```

## Ingestion responsibilities

The ingestion service should verify agent identity, enforce request and field
size limits, validate each event against its declared schema version, and
persist the original normalized observation. Invalid data should be rejected
with an actionable per-event result rather than silently coerced.

ETW and Sysmon may observe the same process. Their events should not be blindly
discarded as duplicates because Sysmon may contribute a command line and hash
that the ETW event lacks. The backend can group observations by
`host.id + process.entity_id`, retain every source record, and build a reconciled
process view from compatible facts.

## Detection responsibilities

Rules should operate on normalized semantics such as:

```text
event.category == "process"
event.type == "start"
process.name == "example.exe"
process.hash.sha256 in configured_indicator_set
```

A rule match should create detection evidence, not immediately erase or mutate
the event. An alert can then contain:

- Alert ID, status, severity, and timestamps.
- Rule ID and exact rule version.
- Host, user, and entity references.
- IDs of every supporting observation.
- A concise explanation of what matched.
- Correlation and suppression history.

Stateful rules can later join process starts with network, file, registry, and
DNS events through stable entity IDs and bounded time windows. Keeping this
logic in the backend lets rules change without redeploying endpoint agents.

## Contract evolution

The backend must support an explicit compatibility window for event schema
versions. Officer must never silently change the meaning or type of an existing
field. Additive or breaking contract changes receive a new schema version, and
the server reports which versions it accepts during agent enrollment or
configuration refresh.
