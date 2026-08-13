# Phase 1: telemetry contracts and process normalization

## Goal

Phase 1 gives Officer a stable internal language before live data starts moving
through the agent. An ETW adapter and a Sysmon adapter should be able to report
the same process start without forcing the rest of Officer to understand either
source's native format.

The implemented flow is:

```text
source adapter -> RawProcessEvent -> EnrichedProcessEvent
               -> normalizer -> PanopticonEvent 0.1 -> JSON boundary
```

The source adapter owns decoding. The enricher owns derived information such as
file hashes and resolved account names. The normalizer owns stable event
semantics. JSON exists only at the boundary where an event will eventually be
spooled or transported.

## Phase 1 deliverables

- A source-neutral `RawProcessEvent` with explicit source provenance.
- A separate `EnrichedProcessEvent`; observed facts are not overwritten.
- A strongly typed normalized process-start event.
- The frozen JSON Schema in `schema/event.schema.json`.
- Stable event IDs and PID-reuse-safe process entity IDs using Windows CNG
  SHA-256.
- Strict JSON serialization and deserialization with explicit nulls for absent
  optional values.
- Contract tests for deterministic identities, PID reuse, normalization,
  round trips, malformed input, and schema presence.

## Critique and design limits

Freezing one giant event structure containing every possible process, network,
file, registry, and DNS field would be easy initially but expensive later. Most
fields would be null, invalid combinations would be representable, and every
new telemetry source would put pressure on a central structure.

Phase 1 therefore freezes the common event envelope and one strongly typed
`process/start` payload. Later categories should receive their own typed raw,
enriched, and normalized payloads. The envelope can remain stable while those
payload contracts evolve deliberately.

The `RawEvent` variant is the extension point for those types. It is intentionally
not a polymorphic base class: a closed variant makes ownership obvious and lets
the compiler force each pipeline stage to handle new event types.

This phase does not collect live events, run as a service, detect threats, write
SQLite, or send data over the network. Those behaviors need the contracts, but
they do not belong inside them.

## Invariants

- `event.category` is `process` and `event.type` is `start` in schema 0.1.
- Required identity and host fields cannot be empty.
- Unknown JSON fields are rejected instead of silently ignored.
- A SHA-256 value is exactly 64 hexadecimal characters and is normalized to
  lowercase.
- A parent PID without a known parent start time never produces a parent entity
  ID.
- Raw and enriched C++ types have no JSON, queue, database, transport, or
  detection dependencies.

## What Phase 2 should build on this

Phase 2 should implement a bounded in-memory event bus and a single live ETW
process collector behind a narrow adapter interface. It should publish
`RawProcessEvent`, not JSON. Backpressure, shutdown, loss counters, and a
synthetic collector test seam should be designed before adding more telemetry
sources.
