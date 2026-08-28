# V3 — Multi-family telemetry (Officer)

V3 expands Officer beyond process creation to five telemetry families:
**process, network, file, registry, image load**. Process collection is
unchanged; the four new families are decoded from Sysmon and normalized into
the same Panopticon event contract, evolved additively to **Schema 0.3**.

Status legend: **implemented** = code merged and unit-tested here;
**tested** = covered by CTest in this repo; **live-verified** = demonstrated on
a real elevated Windows host with Sysmon; **planned** = not in this cycle.

## 1. Architecture

```
Windows telemetry (Sysmon Operational channel, EvtSubscribe)
        EID 1                         EID 3 / 7 / 11 / 12 / 13 / 14 / 23 / 26
          |                                        |
  SysmonProcessDecoder            SysmonTelemetryDecoder            (src/collectors/)
          |                                        |
  RawProcessEvent          RawNetworkEvent / RawFileEvent / RawRegistryEvent / RawImageLoadEvent
          |                                        |            (telemetry::RawEvent variant)
  normalize_process_event   normalize_{network,file,registry,image_load}_event   (src/pipeline/)
          \______________________  ______________________/
                                 \/
                    telemetry::PanopticonEvent  (process block + optional family block)
                                 |
                    serialize_event  ->  one Schema 0.3 NDJSON line on stdout
                                 |
        (consumed by panopticon-detection-engine via its V2 bounded queue / SQLite spool)
```

Separation of concerns is preserved:

* **collectors** decode native Sysmon XML into raw family structs and nothing
  else — no JSON, no identity derivation, no detection, no storage;
* **normalization** (`src/pipeline/normalizer.cpp`) converts a raw family event
  plus a `NormalizationContext` into a `PanopticonEvent`. It never synthesizes a
  field the source did not provide — absent fields become `null`;
* **serialization** (`src/pipeline/serializer.cpp`) is the only JSON boundary.

## 2. Telemetry families and sources

| Family | Source | Sysmon Event IDs | Emitted `event.category` / `type` | Fields (only what the source provides) |
|---|---|---|---|---|
| Process | ETW `Microsoft-Windows-Kernel-Process` + Sysmon | ETW / Sysmon 1 | `process` / `start` | unchanged from V1/V2 |
| Network | Sysmon | 3 | `network` / `connect` | direction, protocol (tcp/udp), source/destination ip+port, destination hostname |
| File | Sysmon | 11 (create), 23 / 26 (delete) | `file` / `create` \| `delete` | operation, path, target_path, previous_path, sha256 (when Sysmon hashes files) |
| Registry | Sysmon | 12 (key add/del), 13 (value set), 14 (rename) | `registry` / `add_key` \| `delete_key` \| `set_value` \| `rename_key` | operation, key_path, value_name, value_type (from the Details type token) |
| Image load | Sysmon | 7 | `image_load` / `load` | path, is_signed, signature_status, sha256 (when Sysmon `HashAlgorithms` includes SHA256) |

**Metadata only.** No packet payloads, no file contents, **no registry value
contents** (`value_data` is never populated by the agent), no memory, no PE
parsing.

## 3. Windows prerequisites

* Windows 10/11 x64 or ARM64.
* **Sysmon installed** with a configuration that logs the Event IDs above.
  Network (3) and image load (7) are **high volume**; scope them in the Sysmon
  config to security-relevant paths/hosts. Broad EID 7 collection should be
  treated as opt-in. Registry rules should scope EID 12-14 to the Run /
  Services / IFEO-class hives.
* Sysmon `HashAlgorithms sha256` if you want `file.hash` / `image_load.hash`
  populated.

## 4. Privilege requirements

Elevated (Administrator) — same as V1. Officer reads the protected
`Microsoft-Windows-Sysmon/Operational` channel and controls its ETW session.
V3 adds **no** new privilege: the four new families come from the same channel
and the same `EvtSubscribe` rights already used for EID 1.

## 5. Schema

`schema_version` is now **`0.3`** — an **additive** evolution of 0.2
(`schema/event.schema.json`):

* `schema_version` accepts `{"0.2","0.3"}`; a 0.2 process event stays valid.
* `event.category` widens to `process | network | file | registry | image_load`,
  with a per-category `event.type` vocabulary enforced by `allOf`/`if`-`then`.
* one optional family block per non-process family; `process` stays required on
  every event as process context.
* `additionalProperties: false` is kept at every level. `deserialize_event`
  enforces exactly one family block for a non-process event and none on a
  process event.

The consumer (`panopticon-detection-engine`) accepts `{0.1, 0.2, 0.3}` and the
V2 reliability layer is telemetry-type agnostic, so 0.3 required no V2 change.

## 6. Build

```powershell
# from an x64 Developer PowerShell (or with vcvars64 imported)
cmake -S . -B build-officer-x64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="<vcpkg>/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build-officer-x64
```

No new dependencies — `tinyxml2` and `nlohmann-json` (already declared) cover
the new decoder. New TU: `src/collectors/sysmon_telemetry_decoder.cpp`.

## 7. Test

```powershell
ctest --test-dir build-officer-x64 --output-on-failure
```

`officer-live-collector-decoder-tests` gains per-family decode + normalization +
Schema 0.3 round-trip checks over four sanitized synthetic fixtures
(`tests/fixtures/sysmon_{network_connect,file_create,registry_set_value,image_load}.xml`),
plus rejection of EID 1 and unknown Event IDs. `officer-core-contract-tests`
covers 0.2 back-compat and family-block rejection. **7/7 CTest cases pass on
x64-windows (MSVC 14.44).**

## 8. Live validation procedure (needs a real elevated Windows host)

```powershell
# elevated PowerShell, Sysmon installed + configured for EID 1,3,7,11,12,13,14
.\build-officer-x64\officer-agent.exe --source sysmon > officer-v3.ndjson
# in another shell, generate one event per family, e.g.:
Invoke-WebRequest https://example.test -UseBasicParsing            # network (EID 3)
New-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\x.txt"  # file (EID 11)
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name X -Value y  # registry (EID 13)
# image load (EID 7) fires as processes load DLLs
# Ctrl+C, then inspect officer-v3.ndjson for one line per category
```

**Live-verified status: not yet done in this cycle** — the build/test path is
validated on x64; live Sysmon capture of the new families requires an elevated
host with Sysmon and is tracked separately, exactly as ARM64/x64 live process
capture is.

## 9. Limitations

* Sysmon is the only source for the four new families; no ETW file/registry
  provider, no minifilter. `file` fires on **create/delete**, not on every
  write.
* `network` is connection metadata only — no bytes, no flow accounting.
* The non-process `process.entity_id` is derived from host + PID + Sysmon
  `ProcessGuid`; it is stable for a process's lifetime but is **not guaranteed
  to equal** the process-start event's `entity_id`. Cross-family correlation to
  a process is by PID/name within a time window.
* `image_load.signature_status` is whatever Sysmon reports (often
  `Unavailable`); `is_signed` may be `null`.
* No shipped Sysmon config yet (see Known issues).

## 10 & 11. Known issues / follow-ups

* No reference Sysmon configuration is shipped; broad EID 3/7 subscription can
  pressure the downstream bounded queue (see `SECURITY_REVIEW_V3.md`, medium
  finding 1).
* `render_event_xml` has no explicit event-size cap before parsing (low finding 2).
* `sniff_event_id` does not bound the digit run (low finding 3).
* Sysmon-XML helpers are duplicated between the process and telemetry decoders,
  kept separate deliberately to leave the V1/V2 process path untouched
  (informational finding 4); extract a shared header as a follow-up.
