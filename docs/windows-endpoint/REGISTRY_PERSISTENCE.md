# Extended native registry persistence inventory

Four independent five-minute workers supplement the existing task, WMI, Run,
Winlogon, AppInit and Startup-folder inventory. They emit canonical durable
begin/page/ordered-manifest records through the same immutable acceptance retry
path. Health identifies each source separately and binds freshness to its
accepted manifest; the persistence domain aggregates all eight relevant state
sources. A failed or stalled mechanism does not serialize the others.

| Source | Selected native configuration |
| --- | --- |
| `active_setup_inventory` | Active Setup Installed Components: default value, StubPath, Version, Locale, IsInstalled and ComponentID |
| `image_execution_inventory` | HKLM IFEO image keys and one level of filter children: Debugger, GlobalFlag, VerifierDlls/Flags, UseFilter, FilterFullPath and MitigationOptions; global/per-image SilentProcessExit monitor/dump settings; Session Manager BootExecute/SetupExecute/Execute and AppCertDlls |
| `com_activation_inventory` | CLSID AppID/LocalService reports, InprocServer32/InprocHandler32 path and threading reports, LocalServer32 path/ServerExecutable, TreatAs/AutoTreatAs references; AppID service/surrogate/RunAs and raw launch/access permission values |
| `startup_approval_inventory` | Raw Run, Run32 and StartupFolder values under Explorer StartupApproved; binary approval-state formats are not interpreted |

Except for HKLM-only image execution configuration, workers inspect the current
collector's HKCU, loaded HKU SID hives and HKLM in explicit requested 32/64 views.
Under LocalSystem, HKCU is the service account's context. HKCR is not used, hives
are never loaded, and the collector does not claim an effective merged COM view.
Unloaded profiles and separate SID `_Classes` hive layouts are not comprehensively
covered. Registry redirection and sharing mean requested views need not denote
different underlying physical keys. Missing keys/selected values are distinct
from denied or otherwise failed native queries.

Each registry branch stops at 256 indexed child keys; IFEO filter children stop
at 32 and loaded-hive discovery at 128. Branch rows expose the limit, examined
indices and incomplete traversal. The complete manifest remains incomplete when
a branch exceeds its bound. These are prefix scans: later keys can remain
unobserved on subsequent captures. Fair rotating traversal/reconciliation and
native change notification remain future work. A false global copy-byte bound
does not establish complete branch traversal; inspect each branch's explicit
index-limit status and the manifest's enumeration status.

Application field/page/row and soft-time bounds apply. Native registry calls do
not have hard allocation or execution deadlines. Indexed reads are non-atomic;
concurrent changes can reorder, add or remove values/subkeys. Captured registry
types and raw bytes survive malformed text and oversized-field refusal. Commands
are not expanded, resolved or executed, COM objects are not activated and no
image/debugger/prevention configuration is changed. Paths, references and access
permission bytes are reported configuration, not verified file identities,
effective authorization, execution, actor attribution or maliciousness.

The native component fixture creates only a new GUID-named namespace under
`HKCU\Software\PanopticonValidation`, preserving realistic relative layouts
without installing actual autoruns, COM classes or IFEO hooks. It checks raw
values/views, missing configuration, native branch truncation, consumer refusal
and persistence-domain freshness, then deletes only its own namespace.

See [validation evidence](VALIDATION.md) for actual component, host and guest
results. Full persistence coverage, authoritative delta/lifetime reconciliation,
execution attribution, policy/privacy controls, protected/system-account/native
fault/OS qualification and remediation remain incomplete.

Native references: [Silent Process Exit](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit/),
[CLSID registration](https://learn.microsoft.com/en-gb/windows/win32/com/clsid-key-hklm),
[LocalServer32](https://learn.microsoft.com/en-us/windows/win32/com/localserver32).
