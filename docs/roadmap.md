# Officer roadmap

## Completed

### Phase 0: repository boundary

- Renamed the endpoint component to Officer.
- Preserved EyeTrace Query as `officer-query`.
- Established agent-only repository ownership.

### Phase 1: contracts

- Added raw, enriched, and normalized process contracts.
- Added deterministic event and process identities.
- Added strict JSON serialization and contract tests.

### Phase 2: live process telemetry

- Added raw Windows ETW process-start collection.
- Added live Sysmon process-create subscription.
- Added source provenance schema 0.2.
- Connected both sources to normalized NDJSON output.
- Added clean normal shutdown and partial-start failure cleanup.
- Validated a from-scratch configure/build/test cycle on Windows x64 (MSVC
  14.44, vcpkg triplet `x64-windows`): all targets build cleanly and all 7
  CTest cases pass. The build system is triplet-driven and required no source
  changes to support x64 alongside the existing ARM64 target. Live ETW/Sysmon
  capture on x64 still needs to be demonstrated on elevated hardware with
  Sysmon installed; only the build/test path is validated so far.

## Proposed next phases

### Phase 3: bounded pipeline and health

- Add a bounded multi-producer event queue.
- Define backpressure and drop policy per telemetry priority.
- Add received, decoded, rejected, queued, dropped, and lost counters.
- Add collector supervision and structured internal diagnostics.
- Move normalization and output off collector callback threads.

### Phase 4: typed telemetry expansion

- Add network connection, file, registry, DNS, image-load, and process-stop
  contracts and schemas.
- Map applicable ETW and Sysmon events into the same semantic contracts.
- Add configurable source, keyword, event-ID, and field selection.
- Preserve unknown optional fields without weakening schema validation.

### Phase 5: endpoint state and enrichment

- Maintain a bounded process table for parent/child correlation.
- Resolve account SIDs and integrity information safely.
- Add cached hashing and Authenticode signer enrichment.
- Normalize device paths and packaged application identities.
- Define enrichment timeouts and failure semantics.

### Phase 6: durable spool

- Batch normalized events into SQLite using WAL mode.
- Define quotas, eviction order, crash recovery, and corruption handling.
- Acknowledge and delete only batches confirmed by ingestion.
- Encrypt or otherwise protect sensitive queued telemetry as required.

### Phase 7: secure delivery and configuration

- Add agent enrollment and a persistent installation identity.
- Deliver compressed batches over authenticated TLS.
- Support acknowledgements, retries, jitter, and server backoff.
- Fetch signed/versioned collection configuration.
- Keep detection rules on the backend unless an explicit offline-detection phase
  is approved later.

### Phase 8: Windows service and operational hardening

- Run under a deliberately selected service identity.
- Add Service Control Manager start, stop, recovery, and upgrade behavior.
- Apply least-privilege ETW and Event Log access.
- Add tamper-aware configuration and binary validation.
- Add health snapshots without exposing raw telemetry.

### Phase 9: validation and release

- Measure event loss, latency, CPU, memory, and disk under load.
- Test collector and network fault injection.
- Test supported Windows x64 and ARM64 releases.
- Add signed release packaging and rollback documentation.
