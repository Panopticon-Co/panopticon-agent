# Windows Security audit semantics and policy visibility

`decode_windows_event_xml` adds the result of `SecurityAuditSemantics::enrich`
under `security_audit_semantics` in the bounded decoded JSON. The enrichment is
additive: it leaves the generic rendered XML and `event_data` array unchanged.
It accepts semantic input only
when the requested and native channels are exactly `Security` and the provider
is exactly `Microsoft-Windows-Security-Auditing`. Other events return an
unavailable result with the source identity mismatch reason.

The current event-ID catalog labels high-value logon/session and explicit
credential events, account and security-group changes, policy changes, process
creation/exit, service installation, scheduled-task changes, Kerberos ticket
events and credential validation. Labels describe the source event category;
they are not detections and do not prove that an event is complete or that an
actor performed the reported operation. Unknown IDs and versions remain in the
original decoded event and are not coerced into a known event type. The event
version is returned verbatim and is deliberately not interpreted by this layer.

Every decoded EventData item is retained in order as a raw element name, raw
`Name` attribute, raw text value, and claim role. Duplicate names are kept.
Roles are `subject_claim`, `target_claim`, `source_claim`, `contextual_claim`,
or `unknown_claim`. They describe what the source field says, not a verified
identity. In particular, a `Subject*` field does not establish the human or
process that caused the operation, and process IDs are not joined to process
entities here. The output explicitly marks actor and process verification as
not performed.

The derived view is bounded to 1,024 fields, 4 KiB per field name, 64 KiB per
field value, and 192 KiB combined name/value text. If a limit is exceeded, the
view reports `partial`; the original rendered XML and existing event data stay
unchanged in the decoded source record and remain the authoritative raw facts.
No password or secret interpretation, normalization, or transformation occurs
in this layer. Existing source-retention and privacy policy remains in force.

`SecurityAuditSemantics::query_system_policy` is called by a separate read-only
state worker every five minutes. It enumerates at most 256 system audit
subcategories, queries their raw advanced audit policy mask, and retains each
GUID, localized display name when available, success/failure bits, and unknown
mask bits. The complete enumerated inventory includes categories relevant to
authentication, account and group management, policy changes, process
auditing, services and tasks. The worker durably commits a begin record before
the API call, bounded pages of at most eight subcategories, then a manifest
with page record IDs and query status. Unavailable and partial API outcomes
are retained as explicit query status; an unavailable query is never emitted
as a healthy empty inventory. The collector never calls an audit-policy
setter.

Health includes worker state, committed capture/page counts, query and commit
refusals, pending durable acceptance, the last committed manifest/query status,
and source capture freshness. The audit-policy capability is refreshed only
after durable manifest acceptance. This worker is independent of the host
inventory worker's existing system-policy sample.

This is system policy visibility only. Per-user and effective-token policy,
policy authority/precedence, policy-change continuity, event-generation and
delivery proof, audit channel state, and real Windows/OS qualification remain
outside this component. `AuditQuerySystemPolicy` may be refused without
`SeSecurityPrivilege` or `AUDIT_QUERY_SYSTEM_POLICY` access; that result is
reported as unavailable and does not prompt a policy change. The native API is
synchronous and has no hard deadline or cancellation mechanism here. It runs
on a dedicated worker, so it does not gate startup, but a hung API call can
delay that worker's stop/join during shutdown. Neither the worker cadence nor
the health timestamp bounds native API duration.

Static review only. This component and worker integration have not been built
or run on Windows and have no dedicated runtime or unit-test evidence.
Event-label coverage, raw-source preservation, field roles, page/manifest
durability, policy API availability, memory bounds, permissions, and returned
masks all require final integration validation and Windows qualification.
