# Schema 0.5 telemetry (V5): fileless and cross-process families

Schema 0.5 is **additive** over 0.4. Every 0.2/0.3/0.4 event is still valid and
byte-identical. 0.5 adds one process event type and four new families, chosen
because they unlock the detection classes 0.3 could not see: fileless execution,
credential theft, and process injection.

| event.category | event.type | Source | Engine event_type | What it unlocks |
|---|---|---|---|---|
| `process` | `stop` | Sysmon EID 5 | `process_terminate` | true process lifetimes |
| `dns` | `query` | Sysmon EID 22 | `dns_query` | C2-by-name, DGA, process→domain |
| `process_access` | `access` | Sysmon EID 10 | `process_access` | LSASS credential dumping |
| `remote_thread` | `create` | Sysmon EID 8 | `remote_thread` | process injection |
| `script_block` | `execute` | PowerShell 4104 | `script_block` | fileless PowerShell, AMSI bypass |

## Schema-version policy

An event declares the schema version that **introduced its family**. A process
start, network, file, registry or image-load event is still `0.3` (or `0.2`); a
process stop, dns, process_access, remote_thread or script_block event is `0.5`.
Consumers that predate 0.5 keep working on the older families untouched. The
detection engine's `OfficerIngestionAdapter` and the manager's wire mirror both
accept `0.1`–`0.5`.

## What each new event carries

All blocks are **observed metadata only** — no payloads, no process memory, no
PE contents. Absent fields are `null`, never guessed.

- **dns**: `query_name`, `query_status`, `query_results` (the resolver's answer
  string exactly as Sysmon renders it; the engine parses the addresses out of it
  but the raw string is preserved).
- **process_access**: the acting process is the normal `process` context (the
  **source**); the **target** is in `process_access.target` (entity_id, pid,
  executable, user). Plus `granted_access` (the Windows access mask as a hex
  string) and `call_trace` (Sysmon's module+offset stack).
- **remote_thread**: same source/target split; plus `new_thread_id`,
  `start_address`, `start_module`, `start_function`. `start_module` is `null`
  when the thread starts in memory no loaded module backs (classic injected
  shellcode).
- **script_block**: `script_block_id`, `message_number`/`message_total` (4104
  splits large blocks), `path`, and the text. **Text handling:** the agent keeps
  at most the first 16384 UTF-8 bytes (cut on a character boundary) in `text`,
  records the full byte length in `text_length`, sets `text_truncated`, and puts
  a SHA-256 of the *whole* block in `text_sha256`. The 4104 event names only a
  PID and a user SID — it has no image path, so `process.executable` is filled
  only from what the agent already observed for that PID (the engine otherwise
  resolves the actor by PID + time).

## Why the source/target split

For process_access and remote_thread the shared `process` block is always the
**actor** (the opener / the injector), and the other process is in the family
block's `target`. This keeps the existing identity join — "which process did
this" — identical across all families, so the engine's `(host, pid, time)`
correlation and the provenance graph need no special cases.

## Running the agent for 0.5

```powershell
# Everything (ETW + Sysmon + PowerShell 4104):
.\officer-agent.exe --source all

# Just the PowerShell script-block channel:
.\officer-agent.exe --source powershell
```

Prerequisites on the host:

1. **Sysmon** with a config that emits EID 5, 8, 10, 22 — merge the rule groups
   from [`docs/sysmon/officer-reference-config.xml`](sysmon/officer-reference-config.xml).
   EID 10 there is scoped to LSASS targets (it is very high volume unscoped).
2. **PowerShell Script Block Logging** for 4104:
   Group Policy → *Windows Components → Windows PowerShell → Turn on PowerShell
   Script Block Logging*, or set
   `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`.
3. An **elevated** PowerShell (ETW/Sysmon/Event-Log subscriptions need it).

## Verifying live capture before pushing

The CTest suite proves the decoders, normalizer and serializer on fixtures, but
CI has no live event source, so it cannot prove the Win32 collectors
(particularly the PowerShell subscription). Run the host smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows_smoke_test.ps1 `
    -AgentPath .\build-officer-x64\officer-agent.exe
```

It runs the agent, generates benign activity (a child process, a DNS lookup, a
script block, a handle open), and fails unless the emitted NDJSON contains
well-formed schema-0.5 events of the `process`, `dns` and `script_block`
categories. `process_access`/`remote_thread` are reported but not required
(they need an attack to appear reliably).

## Recording a benign baseline session

The detection engine's behavioural rarity baseline learns "normal" from benign
telemetry. To produce that telemetry with the finished agent:

```powershell
# Record a few hours of ordinary use to an NDJSON file.
.\officer-agent.exe --source all > benign-session.ndjson
```

Use the host normally (browser, Office, updates, dev tools). Then, in the
detection engine:

```bash
panopticon-detect --rules rules --officer-ndjson benign-session.ndjson \
    --learn-baseline baseline.json
```

See `../panopticon-detection-engine/docs/behavioral-intelligence.md` for how the
baseline is used. Record benign data from a host you have reason to trust clean;
a baseline learned over an existing compromise learns the compromise as normal.

## Known limitations

- **4104 image backfill is live-only within one agent run.** The agent fills a
  script block's image from its own PID cache; across an agent restart the engine
  still resolves the actor by PID + time.
- **Remote-thread and process-access volume.** EID 10 is scoped to LSASS in the
  reference config; broaden only with queue headroom.
- **WMI (Sysmon 19–21) and authentication (Security 4624/4625) are not in 0.5.**
  WMI events carry no originating PID to join on, and logon events need a
  session entity the graph does not model yet. Both are deferred, not forgotten.
