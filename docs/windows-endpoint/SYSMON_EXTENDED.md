# Canonical Sysmon interactions and DNS

Sysmon EID 8, 10 and 22 now use a Windows-specific raw variant and canonical
`windows_sysmon_extended_v1` body through the live subscription, bounded handoff,
factory and protocol-2 encrypted journal. Legacy schema 0.4 is unchanged. The
earlier branch's legacy 0.5 implementation is superseded on this path.

`remote_thread` retains distinct source/target process references, new thread ID,
full-width start address, module and function. `process_access` retains distinct
references, a uint32 access mask as exact decimal text and a bounded call trace.
GUID references remain source-scoped; no native process identity is invented from
PID or rounded Sysmon time. Module/function are source-reported inferences,
as [Microsoft documents](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

`dns` retains query name/status, parsed IPv4/IPv6 and `type: 5` CNAME answers, and
unrecognized answer tokens. Query RR type is null with a reason because EID 22
does not establish it. An IPv6-looking answer cannot imply an AAAA query.
At most 256 answer tokens are interpreted; remaining interpretation is explicitly
unavailable. Query results and traces have a 16 KiB UTF-8-safe presentation bound,
original byte count, truncation flag and SHA-256. Original decoded EventData text
remains separately available under `data.source_facts.windows_event_data` within
the 256 KiB XML admission limit. Original native binary bytes are not retained.

Decoding rejects duplicate/unnamed EventData, ambiguous System fields, wrong
provider/channel, NUL input, malformed numbers, PID/port/mask overflow and invalid
event clocks. EIDs 8/10/22 prefer Sysmon `UtcTime`; EID 3 keeps its existing
SystemTime preference. Missing fields remain null with explicit reasons.
All new strings, target context and vector storage count toward queue ownership.

The reference configuration adds all remote-thread and DNS events and selected
process-access pairs beyond LSASS-only targets. The explicit interpreter/launcher
source list is a coverage limit, not a rate guarantee. It includes the benign live
probe. Installed Sysmon policy is never changed automatically by validation.

Component regressions cover decoding, PID reuse with distinct GUIDs, unresolved
PID-only references, full-width numbers, missingness, conservative DNS parsing,
UTF-8 truncation, malformed admission, queue charging and exact journal reopen.
See [validation](VALIDATION.md) for dated build and live evidence. These tests do
not qualify ETW/Sysmon aliases, DNS Client requester attribution, flow bytes,
capture recall, Manager/ML consumption or the full agent.
