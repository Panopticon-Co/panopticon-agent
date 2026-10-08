# SCM service lifecycle

`officer-agent --service` connects directly to the Windows SCM as the own-process
service `PanopticonOfficer`. It does not install itself or silently fall back to
console capture when SCM dispatch fails. Console invocation remains available.
SCM start parameters are not treated as an arbitrary command/configuration path;
the executable command line supplies the existing validated endpoint options.

The service registers its extended control handler, reports START_PENDING with
no accepted stop controls, initializes the durable runtime, then reports RUNNING
after worker/source startup attempts. RUNNING describes runtime orchestration;
it does not certify sensor coverage. Durable health records expose host mode and
the incomplete service qualification scope. AJ remains degraded in service mode.

STOP/SHUTDOWN requests report STOP_PENDING and signal an owned manual-reset event.
The endpoint owns a duplicate of that event, preserving requests across startup
and keeping the handler's handle alive through cleanup. The handler performs no
inventory joins, network work or journal operations. Native workers/collectors,
raw handoff, response and delivery drain on the endpoint thread. STOPPED is
published once, after endpoint cleanup, with explicit service-specific failures.
Repeated stop/interrogate calls cannot republish terminal status or restore
RUNNING after STOP_PENDING.

Pending checkpoints advance only after actual initialization or join/drain
milestones. No background timer fabricates progress if a native call hangs.
The 30-second wait hint is not a guaranteed shutdown deadline: native COM/RPC/
collector/network calls and joins still require deadline/isolation qualification.
No pause, preshutdown guarantee or automatic failure-restart policy is claimed.
See [Microsoft status guidance](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus).

Service mode rejects relative spool/identity paths and relative enabled delivery,
response ledger, bootstrap, collection or quarantine paths. Credentials and
user-scoped DPAPI journals remain bound to the execution account. A console
user's journal must not be transplanted into LocalSystem service storage as if
it were decryptable; installation/migration needs an explicit supported design.
Executable/configuration ACLs, credential provisioning, signing, least-privilege
broker separation, secure configuration/update and MSI lifecycle remain open.

## Validation workflow and limits

`officer-service-host-tests` exercises transitions, real-progress checkpoints,
duplicate controls, stop/readiness races, publication failure, success/failure
exit codes and exactly-once terminal publication using an injected status sink.
These are component tests, not actual SCM start/stop evidence.

`tools/validate_windows_service.ps1 -PackagePath <staged-package>` is prepared for
the dedicated PANOPTICON-WIN guest after its runtime prerequisites are installed.
It verifies package hashes, refuses an existing service, creates a manual-start
LocalSystem fixture, checks executable/account/PID binding, and exercises two
start/stop iterations against the same owned journal directory. It retains a
report and deletes only its matching stopped fixture. A timeout preserves a
still-active service; it never kills/restarts it solely because observation ended.
It does not claim record-content recovery: user-scoped DPAPI readback under a
different guest account would be invalid. Same-account recovery, privileged
sensor evidence, fault/shutdown/reboot/security matrices remain qualification work.
The script subsequently completes in the dedicated guest: two actual LocalSystem
start/stop cycles verify exact executable/account/PID binding and Stopped status
with native/service-specific exit codes zero. The owned journal grows from
25,579,520 to 49,094,656 bytes. Exported report:
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\evidence\service-wave-20261007/service-report.json`.
This is positive SCM lifecycle evidence, not LocalSystem content recovery or full
shutdown/fault/OS qualification. MSI installer, signing and update remain missing.
