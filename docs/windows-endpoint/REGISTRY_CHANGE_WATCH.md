# Windows registry change notifications

`RegistryChangeWatch` is an independent, read-only source that subscribes with
`RegNotifyChangeKeyValue` with read-only `KEY_NOTIFY | READ_CONTROL` access. It
does not enumerate or read registry values. The selected 64-bit-view subtrees are:

| Root ID | Hive | Watched subtree |
|---|---|---|
| `hklm_current_version` | HKLM | `Software\Microsoft\Windows\CurrentVersion` |
| `hkcu_current_version` | HKCU/current caller | `Software\Microsoft\Windows\CurrentVersion` |
| `hklm_nt_current_version` | HKLM | `Software\Microsoft\Windows NT\CurrentVersion` |
| `hklm_services` | HKLM | `System\CurrentControlSet\Services` |
| `hklm_lsa` | HKLM | `System\CurrentControlSet\Control\Lsa` |

These parent subtrees include selected Run/RunOnce, Winlogon/AppInit, service,
and LSA configuration areas. Startup inventory separately reads selected
Run/RunOnce and Winlogon/AppInit values in both registry views. This source
does not claim that its broad parent notifications are limited to those specific
mechanisms. It does not watch other caller/loaded-user hives or the 32-bit
registry view.

Each signal yields a durable `registry_change_observation` with root/hive/path
provenance, UTC receipt time and a collector-local sequence. It only means that
Windows signaled a change somewhere below the watched path. The changed child
key, value name/data, prior value, mutation operation, caller/process and actor
are unknown. No value diff or attribution is inferred. Events mark
`reconciliation_required=true` and `reconciliation_triggered=false`; no
reconciliation scan is launched by this source.

The source queue is bounded at 256 notification objects. If it fills, it drops
newly received notifications and retains per-root cumulative drop counters and
a bounded pending range/count. The durable consumer writes
`registry_change_gap` records before reporting those losses as committed. A
record refusal retains the current immutable serialized record for retry; on
shutdown, an unaccepted record is reported in health and is not claimed as
durable. Queue-loss counts cover only notifications already delivered by the
API and rejected by this queue. Windows notifications are coalescing signals,
and changes during a notification re-arm race or while Windows coalesces them
cannot be counted. Therefore neither event count nor gap count equals the number
of registry writes.

Stopping is terminal for a watcher instance; a new instance must be created to
restart collection. Its local sequence and in-memory queue/loss state reset on
process restart. Health reports each root as active, unavailable, blind or stopped,
including cumulative queue drops, current/final uncommitted queue depth and the local sequence. Missing/inaccessible
roots are retried every 30 seconds. `RegOpenKeyExW`, `RegNotifyChangeKeyValue`
and their shutdown join have no hard deadline/cancellation guarantee; this
worker is started independently so native API delays do not synchronously block
main-thread startup, but they can affect eventual shutdown. Registry changes
only notify; this source does not change audit policy, registry policy, channel
configuration or endpoint response state.
