# Durable source supervision baseline

The ETW/Sysmon supervisor stores collector status in the existing encrypted
`DurableJournal` source-checkpoint table. It samples each loop, emits a gap as
soon as a transition is observed, and checkpoints otherwise-quiet status at
most every 30 seconds. Quiet samples advance only the checkpoint; they do not
manufacture telemetry records. A status transition,
counter change, reset, or startup with no comparable sample creates a canonical
`source_loss` record. That gap record and the new comparison checkpoint commit
in one FULL/WAL transaction, so a failed commit does not acknowledge the sample
or lose its pending report. Retries keep the same record bytes and CAS revision.

Checkpoint writes use a per-source revision and are DPAPI-protected with the
journal's protected directory and FULL/WAL durability settings. The checkpoint
is bound to the current collector generation. On process restart, counters from
the previous collector lifetime are not subtracted from new lifetime counters;
the first sample instead reports `startup_continuity_unknown` and starts a new
comparison interval. A failed checkpoint read is surfaced as unavailable
supervisor continuity. This does not establish ETW/Sysmon provider continuity,
recover native events missed while the service was stopped, or make sampled
native loss counters authoritative. Source event sequence/bookmarks and
system-level loss proof remain open.

This implementation is source-only in the current wave. Build, unit, restart,
disk-fault, power-loss and real-Windows verification remain pending final
integration; do not describe sampled supervisor checkpoints as verified sensor
continuity.
