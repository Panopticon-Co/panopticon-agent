# ADR 003: derive process identity from host, PID, and start time

- Status: accepted
- Date: 2026-08-13

## Context

Windows reuses process IDs. A PID identifies a process only within a limited
time window, so using `host.id + pid` would eventually assign the same identity
to unrelated processes. Random identifiers would avoid collisions but would
not be reproducible when the same source record is replayed.

## Decision

Officer derives a process entity ID as a lowercase SHA-256 digest over a
length-delimited, versioned representation of:

```text
host.id + process.pid + process.start_time_in_UTC_nanoseconds
```

The visible identifier is `proc_` followed by the 64-character digest. Hashing
uses the Windows Cryptography API: Next Generation (CNG), provided by
`bcrypt.dll`.

Event IDs use a separate `evt_` domain and include source provenance in addition
to the process identity facts. Keeping entity and event domains separate avoids
confusing “this process” with “this observation of the process.”

## Consequences

- Replaying the same facts produces the same identifier.
- A reused PID receives a different identifier when its start time changes.
- The same PID and start time on different hosts remain distinct.
- Parent identity cannot be safely derived from parent PID alone. It remains
  null until the parent start time is known.
- Changing the canonical representation requires a new domain version rather
  than silently changing existing IDs.
