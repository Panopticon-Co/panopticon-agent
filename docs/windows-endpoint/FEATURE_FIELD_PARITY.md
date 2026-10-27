# Windows feature-field parity

Updated 2026-10-22. This is a producer/consumer handoff, not trained-model or fleet
qualification. The supplied Detection Engine archive has no verified commit.
`features.py` schema 2 extracts graph-backed process features as of a time; the draft
ML plan proposes a separate stateless start-time featurizer. Later behavior/lifetime
must not leak into start-time training or scoring.

## EID1 source-context increment

Canonical endpoint record 1.0 retains additional EID1 fields under
`data.source_facts.process.sysmon_fields`. The block has:

- `format: windows_sysmon_process_fields_v1`, `event_id: 1`;
- `fields`: the nine nullable, originally spelled field names below;
- `unavailable`: `{field, reason: source_field_absent}` for each absent field;
- `values_interpreted: false`, `native_creation_ticks_derived: false`.

Present text is retained exactly after XML decoding. Empty text and Sysmon `-`
placeholders differ from absent fields. Invalid UTF-8 uses the existing reversible
hex representation. No token integrity, session join, executable trust or native
creation tick is inferred from text. ETW/EID5 do not manufacture this optional block.
Every owned string capacity counts toward bounded queue admission. Raw XML allocation
bounds, large-record admission and per-field truncation policy remain broader work;
this increment does not silently truncate or zero-fill.

Paths in this table are relative to `data.source_facts`. "Retained" means implemented
here; component results are recorded in `VALIDATION.md`. An elevated live EID1 probe
now verifies all nine fields against the exact native XML and durable canonical
recovery. Earlier unelevated access was denied; channel permissions were not changed.

| Canonical field | Windows source(s) | Sysmon/OTRF field name | Unavailable reasons | Status |
|---|---|---|---|---|
| `process.parent_executable` | EID1 | `ParentImage` | Absent source value | Existing decoded fact; consumer parent-path mapping remains |
| `process.sysmon_fields.fields.ParentCommandLine` | EID1 | `ParentCommandLine` | `source_field_absent`; optional block absent for other sources | Retained; consumer mapping required |
| `process.sysmon_fields.fields.IntegrityLevel` | EID1 | `IntegrityLevel` | Same as above | Retained as source-reported text |
| `process.sysmon_fields.fields.OriginalFileName` | EID1 | `OriginalFileName` | Same as above | Retained; no trust claim |
| `process.sysmon_fields.fields.CurrentDirectory` | EID1 | `CurrentDirectory` | Same as above | Retained |
| `process.sysmon_fields.fields.LogonId` | EID1 | `LogonId` | Same as above | Retained exactly; auth-session join remains |
| `process.sysmon_fields.fields.LogonGuid` | EID1 | `LogonGuid` | Same as above | Retained as a source alias |
| `process.sysmon_fields.fields.TerminalSessionId` | EID1 | `TerminalSessionId` | Same as above | Retained without numeric narrowing |
| `process.sysmon_fields.fields.Hashes` | EID1 | `Hashes` | Same as above | Complete reported string retained; typed IMPHASH mapping remains |
| `process.sysmon_fields.fields.UtcTime` | EID1 | `UtcTime` | Same as above | Exact source text separate from parsed event time |
| `process.start_time_ticks` | Kernel process ETW | No equivalent native token established from OTRF | Not supplied by Sysmon | Existing native value; exact cross-source binding remains open |
| Process stop/lifetime | ETW / EID5 | `UtcTime`, `ProcessGuid`, `ProcessId` | Stop missing / instance unresolved | Existing stop path; complete lifecycle parity remains open |
| Flow duration / bytes | TCP/IP ETW | Not supplied by EID3 adapter | Source absence / missing implementation | Open; never substitute zero |
| Typed DNS answers | EID22 / DNS Client | `QueryResults`, `QueryStatus`, `QueryName` | `dns.query_type` not reported by EID22 | Canonical `dns` family (IP/CNAME answers, bounded results); DNS Client source open |
| Process interaction | EID8 / EID10 | Source/target fields, access/trace/thread/start fields | Target creation ticks not supplied by Sysmon | Canonical `remote_thread` / `process_access` families; live EID8/10 capture not yet recorded |
| Own-image signer | Image/signature enrichment | EID7 signatures describe loaded modules | No verified own-image association | Open; not an existing schema-2 process feature |
| Image writer/age | File events / graph history | `TargetFilename`, process context | Instance/history unavailable | Full attribution qualification open; USN/FIM cannot prove writer |
| PowerShell instance | 4104 / durable process history | `ExecutionProcessID`, script fields | PID alone cannot prove instance | Exact durable resolution remains open |
| Auth/session entity | Security logs | 4624/4625/4634/4648/4672, Kerberos | Source privilege / missing mapping | Native log evidence exists; typed joins/OTRF mapping remain open |
| WMI / pipes | Sysmon / WMI Activity | EID19/20/21, EID17/18 | Missing mapping / actor unverified | Supplied OTRF adapter skips these |

## Consumer coordination

1. Verify that the deployed Manager v2 path and pinned canonical contract preserve the
   additional `data.source_facts` block before qualification.
2. Map the selected fields explicitly in engine canonical ingestion. The supplied OTRF
   adapter drops parent executable/command, integrity and OriginalFileName. Extend live
   and dataset mappings together with shared golden vectors and versioned missingness.
3. Keep graph-feature and model-featurizer versions distinct. Missing, empty, source `-`
   and numeric zero cannot be silently conflated.
4. Legacy serialization is unchanged. This is additive decoded evidence in canonical
   endpoint record 1.0, not legacy 0.5/0.6 support.
5. OTRF labels describe recordings, not every event/process. No model, recommendation
   policy or engine implementation changes in this producer increment.

Check installed-version availability against real output and
[Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Live verification covers the owned benign EID1 scenario on this development host.
Dedicated-VM, Manager acceptance, capture recall and train/serve qualification remain open.

## Wire contract

Family definitions, timestamp/identity/outcome semantics, fixtures and
consumer-compatibility results live in panopticon-contracts
`docs/ENDPOINT_TELEMETRY_CATALOG.md` and `schema/endpoint-record/1.0/families/`
(branch `windows-endpoint-telemetry-contract`). This table stays the field-level
ML parity view; the catalog is authoritative for wire semantics.
