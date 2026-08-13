# Officer Query

`officer-query` is the preserved EyeTrace Query v0.1 historical telemetry tool.
It reads records already stored in `Microsoft-Windows-Sysmon/Operational`; it
does not subscribe to live events or run as a service.

Supported Sysmon event IDs:

| Event ID | Telemetry |
| ---: | --- |
| 1 | Process creation |
| 3 | Network connection |
| 11 | File creation |
| 12 | Registry create/delete |
| 13 | Registry value set |
| 14 | Registry rename |

Query three process events and write the same NDJSON to stdout and a temporary
file:

```powershell
.\build-officer-arm64\tools\query\officer-query.exe `
  --event-id 1 `
  --limit 3 `
  --output "$env:TEMP\officer-query.ndjson"
```

Use `--format xml` to inspect source XML. Do not commit raw XML, NDJSON, or EVTX
files. Sanitized fixtures live under `tests/fixtures/`.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Invalid command-line arguments |
| 3 | Windows Event Log acquisition failure |
| 4 | XML or telemetry parsing failure |
| 5 | Output-file failure |
