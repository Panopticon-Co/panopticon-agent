# Authenticated capture freshness

New Windows records contain `capture_clock: windows_uptime_ms` and decimal
`capture_uptime_ms`. This is the time the canonical record was constructed, not
the source event's occurrence time or proof that every sensor was working.
The clock is boot-scoped; missing native boot identity cannot establish age.

Before a canonical upload, Uploader requests an authenticated one-use Manager
challenge. The nonce is random, agent-bound, valid for 15 seconds and retained as
a digest in one row per agent. The uploader reports its immutable installation,
boot, collector generation/epoch and current send uptime. Optional challenge
failure never blocks evidence delivery. Delivery health exposes challenge-failure
count and whether the last receipt acknowledged capture-age facts.

Manager migration 15 atomically consumes the challenge with record ingestion.
Only matching installation/boot/generation/epoch and nonnegative clock differences
establish capture age. At first receipt, the reported upper age is send uptime
minus capture uptime, plus the complete server challenge interval and a 100 ms
clock quantization guard. Subsequent reads add elapsed server uptime. Under the
current default, capture is fresh for at most 90 seconds; older capture is stale.
This bound depends on authenticated endpoint reporting and clock qualification,
not hardware attestation. The guard and interval require the full OS/workload
matrix before production qualification.

Age evidence is immutable per accepted original. Duplicate delivery never renews
it, and a nonce cannot prove another request. Expired/replayed/malformed proof,
future uptime, boot/scope mismatch or missing facts stay unverified while records
remain durable. A Manager process epoch prevents persisted elapsed-clock facts
from retaining freshness across restart. Multiple Manager workers currently need
consistent routing to the process that issued the challenge; cross-worker proof
is conservatively unverified, not silently trusted.

Elapsed clocks include suspend time: Windows uses
[GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)
with [Windows sleep/hibernation semantics](https://learn.microsoft.com/en-us/windows/win32/sysinfo/windows-time),
and Linux Manager hosts use
[CLOCK_BOOTTIME](https://docs.python.org/3/library/time.html#time.CLOCK_BOOTTIME).
A Manager without a supported suspend-aware clock reports the optional challenge
unavailable and continues canonical ingestion. Wall-clock ordering or receipt
time alone never establishes freshness.

Latest projection metadata now separates `capture_freshness` (fresh/stale/
unverified), decimal reported capture-age bound, ordering and
`observation_freshness` (still unverified). Consumers must combine ordering and
capture freshness and inspect the actual capability states. A fresh captured
health record can correctly report unavailable/blind sensors. It cannot prove
truthful native coverage, recent occurrence of an old event, or a complete current
host inventory. Source heartbeat/loss supervision, immediate/priority health,
Console stale/blind rendering, policy-controlled freshness budgets, controlled
installation replacement, VM suspend/reboot/restore and distributed Manager
qualification remain open P0 work.

Regression evidence covers old offline capture, aging, replay, immutable duplicate
receipts, expiration, Manager restart, boot/generation/epoch/install mismatch,
unsupported clocks, malformed/duplicate context keys and exact uint64 bounds.
The real native WinHTTP HTTPS harness verifies capture-age acknowledgment plus
Manager fresh-capture metadata. It also verifies observation freshness remains
unverified. Harness cleanup retries transient Windows file locks only in its
resolved, verified test-owned temporary directory.
