# Sysmon reference configuration for Officer V3 telemetry

`officer-reference-config.xml` in this directory is a **reference / validation**
Sysmon policy, not a production mandate. Officer reads the
`Microsoft-Windows-Sysmon/Operational` channel through `EvtSubscribe`; it never
reads this file. The file only expresses the Sysmon *policy* that causes
Officer's five telemetry families to populate.

## When you need it

Officer's V3 collector subscribes to Sysmon Event IDs
`1, 3, 7, 11, 12, 13, 14, 23, 26`. If the host's Sysmon configuration does not
*log* an Event ID, Officer emits nothing for that family. A stock
process-creation-only Sysmon config (the situation during early Panopticon work)
produces the `process` family and nothing else.

## What it enables

| Event ID | Sysmon element | Officer family / type | Scope in this reference |
| --- | --- | --- | --- |
| 1 | `ProcessCreate` | `process` / `start` | all process creations (the V1/V2 baseline) |
| 3 | `NetworkConnect` | `network` / `connect` | all connections except loopback |
| 7 | `ImageLoad` | `image_load` / `load` | **only** modules loaded from user-writable paths (`\AppData\Local\Temp\`, `\AppData\Roaming\`, `\Downloads\`, `\ProgramData\`, `\Users\Public\`) — this is what `DET-IMG-001` inspects, and it keeps a high-volume event ID bounded |
| 11 | `FileCreate` | `file` / `create` | autostart + user-writable staging locations |
| 12 / 13 / 14 | `RegistryEvent` | `registry` / `add_key`,`set_value`,`rename_key` | `Run` / `RunOnce` / `Shell Folders` / `Winlogon` / Image File Execution Options / `Services` |
| 26 | `FileDeleteDetected` | `file` / `delete` | optional; Startup + Temp + ProgramData |

## What it intentionally excludes

- **No `<ArchiveDirectory>`.** Sysmon's file-archiving feature persists the full
  contents of deleted files to disk. Officer is metadata-only, so archiving is
  never enabled and Event ID **23** (`FileDelete`, the archiving variant) is not
  used — Event ID **26** (`FileDeleteDetected`) carries the same path/operation
  metadata without contents.
- **No clipboard capture, no WMI events, no DNS-query events, no named-pipe
  events.** None feed a V3 family and several carry sensitive content.
- **No registry value data.** Sysmon Event IDs 12–14 do not include value data,
  and Officer discards the `Details` type token after mapping it to a `REG_*`
  name.

## Applying it

This is a whole-config file. On a host with an existing managed Sysmon
deployment, **merge only the Event IDs you are missing** into your own config
rather than replacing it. On a dedicated test host:

```powershell
# apply
Sysmon64.exe -c officer-reference-config.xml
# verify what is now effective
Sysmon64.exe -c
# revert to your previous config
Sysmon64.exe -c <your-previous-config>.xml
```

Validated against Sysmon v15.21 (config schema 4.90): loads with
`Configuration file validated. / Configuration updated.` and all six rule groups
parse.

## Volume note

Broadening Event ID 7 (image load) or Event ID 3 (network) beyond the scope
above materially increases event volume. Officer currently performs
decode/normalize/serialize on the acquisition callback thread and has no
bounded queue of its own (that is a later roadmap phase), so a very high Sysmon
event rate can outpace it. See `../V3_TELEMETRY.md` section 9.
