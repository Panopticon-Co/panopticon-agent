# Officer contributor notes

- Keep the program C++20, Windows-native, and beginner-readable.
- Do not commit raw telemetry; fixtures and sample output must be sanitized.
- Build and test native code only on Windows; state verification limits clearly.
- Keep collectors independent of JSON, transport, storage, and detection logic.
- Officer is the Panopticon endpoint agent. Do not implement the server,
  detection engine, console, or arbitrary-command response actions here.
- Preserve `officer-query` as the historical Sysmon diagnostic utility.
