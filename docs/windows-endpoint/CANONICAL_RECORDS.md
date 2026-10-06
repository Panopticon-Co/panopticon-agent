# Canonical identity, provenance and record transport

Live ETW/Sysmon collector output now uses endpoint record 1.0. The canonical contract and semantic invariants live in [the contracts repository](../../../panopticon-contracts/docs/ENDPOINT_RECORD_1.md). Legacy schemas remain separate compatibility formats; their entity formulas are not used as canonical process identity.

`ProcessInstanceStore` derives native identity from host, boot, PID and every native creation tick. It never rounds timestamps, probes the current PID to guess a historical instance, or merges sources by millisecond proximity. Source GUID references use an explicit provider/channel namespace and retain source-scoped resolution. Unresolved references preserve observed PID/facts and carry null entity IDs. Parent PID alone remains unresolved. A bounded resident table counts admission failures instead of suppressing accurate observation identity; full durable host state and lifecycle reconciliation are still required.

Boot identity dynamically queries NT `SystemBootEnvironmentInformation`. The private structure/information-class definition is corroborated by [System Informer's primary header](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h). Microsoft warns that [NtQuerySystemInformation may change or be unavailable](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation). The endpoint checks success/layout/nonzero GUID, reports unavailable boot coverage on failure, and does not approximate boot identity using wall clock minus uptime. Without boot scope, native tokens remain explicitly unscoped. The current development host returns a consistent native boot identity; the approved Windows/ARM64/security-configuration matrix is not qualified.

Canonical envelopes separate device, installation, enrollment and boot identities; retain native event nanoseconds and opaque uint64 tokens as decimal strings; and add a random collector epoch plus ordered sequence. Source continuity currently remains unverified. Provider-loss counters, native header/version/opcode facts, bookmarks and durable live gap records remain work.

The endpoint journals observations and health offline. Uploader separates protocol-1 legacy batches from protocol-2 canonical batches and posts canonical data to authenticated `/api/v2/endpoint/records`. Manager verifies enrolled host/agent, process digest/scope, uncertainty and process payload consistency, rejects identity collisions without overwriting evidence, and commits before receipts. Generic categories preserve the full endpoint surface rather than the old five-family constraint.

Decoded original fields now survive under `data.source_facts`, independent of
normalized aliases; cache context is separate under `data.enrichment`. Failed
normalization or serialization produces durable `normalization_failure` evidence
when the journal accepts it, preserving exact tokens/time and invalid text bytes.
This is decoded-fact retention, not original native byte retention. See
[representation, provenance and limits](SOURCE_FACTS.md).

Manager migration 13 makes retained canonical records a durable Detection queue,
including existing records on upgrade. Both protocols receive bounded claim
capacity; stale claims recover and poison records remain visible as failed.
The Detection Engine validates references and keeps canonical exact/source
entities separate from its legacy PID/time heuristic. Unresolved activity and
parents never inherit a guessed instance. Known families reach existing rules;
other record kinds/domains remain available under explicit vocabulary and full
domain payload. Canonical alerts retain triggering endpoint/subject/provenance
context and use agent-scoped SHA-256 replay identity. The native WinHTTP HTTPS
fixture reaches a real rule while retaining every native creation tick.

This closes the record-to-Detection routing gap, not complete fleet qualification.
Persistent graph reconstruction, full domain state/rules, response leases and
command/result 2, evidence transfer and Console investigation remain unfinished.
The generic state/evidence/command-result envelopes do not mean complete host
inventory, forensic transfer or command/result 2 implementation exists.
Native `host_inventory` state now exists as a versioned, partial non-atomic
snapshot with query-specific availability; see [host state](HOST_STATE.md).
Latest state uses committed generation/sequence ordering, with explicit unverified
observation freshness; see [ordering and its limits](STATE_ORDERING.md).
Bounded live age/proof, controlled installation replacement, health priority delivery, full
service/installer identity provisioning and enrollment decoupling remain open.
