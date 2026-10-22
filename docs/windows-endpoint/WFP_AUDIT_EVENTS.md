# Windows Filtering Platform Security audit events

The additive `security_audit_semantics` result now labels only these events when
the existing source guard confirms the exact `Security` channel and
`Microsoft-Windows-Security-Auditing` provider:

| Event ID | Source event role |
| --- | --- |
| 5152 | `wfp_packet_blocked_source_event` |
| 5156 | `wfp_connection_permitted_source_event` |
| 5157 | `wfp_connection_blocked_source_event` |

Microsoft documents 5152 as a packet blocked by Windows Filtering Platform,
5156 as a permitted connection, and 5157 as a blocked connection. The labels
classify the event ID only; they do not prove a particular firewall rule caused
the decision or establish effective policy. Event 5152 can be generated for
each blocked packet, so enabling the corresponding audit policy can create high
event volume. See Microsoft's [5152](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152),
[5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156),
[5157](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157), and [Filtering Platform Connection audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection) references.

The original rendered XML and ordered EventData remain authoritative and
unchanged. This addition interprets no fields. Reported process IDs, executable
names/paths, addresses, ports, direction and filter identifiers remain
unverified source claims; there is no process-instance, endpoint, rule or
effective-filter attribution. Unknown event IDs and versions stay unclassified
by this addition. Existing raw-source privacy and retention policy applies;
WFP event records can contain executable paths and network endpoint data and
should be treated as sensitive.

This is source-only. The event subscription already uses the Security channel;
no audit policy is enabled or changed by the collector. No build, tests or
Windows runtime validation were run for these labels. Audit-policy enablement,
event/version coverage, volume, privacy/retention and Windows qualification
remain open. See [Security audit semantics](SECURITY_AUDIT_SEMANTICS.md).
