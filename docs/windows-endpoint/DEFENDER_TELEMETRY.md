# Microsoft Defender Operational event semantics

The existing Windows Event Log worker subscribes to
`Microsoft-Windows-Windows Defender/Operational` and retains rendered XML and
ordered EventData. The decoder now adds exact-provider/channel labels for a
bounded set of documented events:

| Event IDs | Source label |
|---|---|
| 1116, 1117 | Threat detected; remediation action reported |
| 1121, 1122, 1129 | ASR block, audit, and user override events |
| 3002, 3007 | Real-time protection failure and recovery |
| 5000, 5001, 5007, 5008, 5013 | Real-time protection enabled/disabled, configuration change, engine failure, and tamper-protection-blocked change |

Only the source event role is interpreted. Raw fields remain unchanged, and
process/actor/action-result attribution is not independently verified. An event
label does not establish that Defender is installed, enabled, healthy, or the
active antivirus product. Security product posture is a separate capability
and must report its own scope and availability.

Retained XML/EventData can include threat names, file paths, usernames, and
configuration values. Collection, access control, encryption, retention, and
privacy review must account for those fields. Channel subscription success does
not prove complete event coverage; disabled channels, clearing, rollover,
privilege limitations, source gaps, and OS differences remain qualification
items. This addition is source-only and has not been built or verified on
Windows.

References: [Microsoft Defender Antivirus event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus),
[Attack surface reduction events](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events).
