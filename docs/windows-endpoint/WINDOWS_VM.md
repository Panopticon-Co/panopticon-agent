# Dedicated Windows endpoint validation VM

Latest update: the user now reports Windows licensing **active for 90 days**.
The native licensing probe confirms `LicenseStatus=1`,
`GracePeriodRemaining=129579` minutes (approximately 90 days) and guest UTC
`2026-10-06T23:04:54.6144278Z`. The reported EvaluationEndDate is a sentinel,
not a usable expiry date. This supersedes the earlier expired desktop watermark.
Guest Control again returns `panopticon-win` with exit zero; shared-folder
package access succeeds. Its token is non-elevated; normal UAC RunAs launches
the validation harness in the interactive administrator session. No UAC/security
policy is weakened. Host evidence is recorded in
[process graph](PROCESS_GRAPH.md); it does not qualify guest execution.

The initial elevated run `C:\ProgramData\PanopticonValidation\run-20261006-160841`
executes the component list but records null PowerShell ExitCode values. It then
fails before endpoint capture because the default task settings object lacks
the attempted Enabled property. Those results are not counted as passing native
validation. Export is preserved in
`evidence/guest-wave-initial-20261007` on the host. The harness now retains the
original process handles and reads native exit codes (host probes verify 0/7),
constructs disabled/hidden task settings explicitly and checks the owned live
stop against the durable graph. Latest hashed package:
`staging/build-20261007-044305`.
The corrected run completes in `run-20261006-161448`: all 21 native component
executables return zero, 1,164 originals and 18 lifecycle originals survive
identical readbacks, and the owned ETW stop plus retained birth/stop graph match
exact native target identity/exit evidence. Six native log channels include
privileged Security. Root-level evidence export and package/schema/Manager
verification succeed in `evidence/guest-wave-corrected-20261007`; recursive export
was refused and journal ACLs were not weakened. See [validation](VALIDATION.md).
Positive parent ancestry, full source coverage, compatibility and soak remain
unqualified. The separate LocalSystem service fixture completes two start/stop
cycles with executable/account/PID binding, zero native/service-specific exit
codes and journal creation/growth. Content recovery under LocalSystem remains
unverified; the current-user runtime readback cannot prove cross-account DPAPI.
Report: `evidence/service-wave-20261007/service-report.json`.

The owned service is confirmed absent with SCM error 1060 after cleanup. Normal
shutdown applies Windows updates, then reaches authoritative `VMState=poweroff`.
Cold snapshot `endpoint-native-baseline-26100-20261007` is successfully created,
UUID `febd5f8d-0aca-44a4-a2f8-54249b885071`. It retains installed prerequisites
and native validation evidence; no agent/service fixture is running. Older
installation-stall snapshots are preserved. Restore only with the owned VM off
and new evidence exported; then start with the documented concurrency allowance.
Snapshot creation is verified; a destructive restore exercise has not been run.

Current user operating policy, 2026-10-07: **Linux and Windows may run
concurrently**. The user reports having reached the Windows desktop and explicitly
reauthorized Windows startup while Linux is running. This supersedes the earlier
off-while-Linux-on request. The Start action permits concurrency, remains restricted
to the owned Windows guest and is idempotent for an already-running guest. Its
memory headroom check can be overridden for the authorized concurrent setup;
other guests are never stopped or reconfigured. The owned guest was started
headless with its existing four-vCPU/4096 MiB allocation. Initial observation
shows Windows boot activity; desktop/Guest Control readiness will be independently
checked before recording guest endpoint validation.

Readiness update: `diagnostics\desktop-recheck3-20261007.png` independently
shows the Windows 11 Enterprise LTSC desktop. Guest Additions run level is zero,
so guest control and shared-folder transport are not available yet. The desktop
watermark reports **Windows License is expired**. No license bypass or clock
change is attempted; a valid license or legitimate renewed evaluation is required
for sustained qualification. The latest hashed Release package is
`staging\build-20261007-040212`, including Device Guard capture and schema-5
process history. Guest endpoint execution remains unverified until that package
is installed and exercised. Earlier setup-stall observations below are historical.

Guest Additions setup: normal guest shutdown through Windows completed; the
official locally installed VirtualBox 7.2.14 additions ISO was attached to the
owned SATA optical drive and the guest booted back to its desktop. ISO SHA-256:
`4F51A073296DE31CCE53924860549149BE5DC339F65DCD1DBF34FD7ACCEFE8FB`.
An elevated native Windows signature check reported Valid and Oracle America,
Inc. for `VBoxWindowsAdditions-amd64.exe`; its silent installer returned zero.
Evidence: `diagnostics\addons-install-progress2-20261007.png`. Run level one
appeared, but Guest Control initially reported not ready. A normal Windows
restart was requested after confirmed installer completion to activate drivers.
This does not yet prove working Guest Control/shared folders or endpoint tests.
The updated guest harness/package is `staging\build-20261007-040615`.

After restart, Guest Additions reached run level two (7.2.14 r174565). Guest
Control successfully executed `cmd.exe /c hostname`, returning `panopticon-win`
and exit zero. A subsequent PowerShell elevation/package-access probe timed out
while PID 7016 was still reported started; the owning session later closed with
a timeout and enumeration confirmed no active guest sessions. A separate mkdir
attempt then failed to establish its guest session. These are terminal access
failures, not running endpoint tests. Desktop framebuffers remain available, but
normal Guest Control/file transfer and repeatable responsiveness are unqualified.
The later desktop screenshots display 03:43 on 2026-10-06 versus the earlier
04:06 on 2026-10-07; this observed wall-clock regression also needs investigation.
No clock/license workaround is applied. Both VMs remain running under the latest
user authorization; Linux is untouched. Endpoint execution in the guest remains
pending despite successful desktop boot and the one hostname probe.

Historical off-policy enforcement:
The in-flight second-stage diagnostic snapshot completed, UUID
`cc24402f-0d19-4d1e-9b0a-178c9775e6b8`. Windows was then explicitly powered off
and verified `VMState="poweroff"`; only the Linux VM remained in runningvms.
No second recovery reset was issued. The start guard was exercised with
`-AllowMemoryPressure` and correctly refused while Linux was active. The guest's
four-vCPU/4096 MiB configuration is retained. Snapshots remain unqualified setup
evidence, not clean baselines.

2026-10-06 discovery: VirtualBox 7.2.14 and VMware Workstation/VIX are installed;
the host reports an active Microsoft hypervisor. CPU virtualization flags are
masked under that hypervisor and are not proof of unavailable virtualization.
VirtualBox already runs the separate Ubuntu `panopticon-endpoint-dev` VM with
4096 MiB/six vCPUs. It remains untouched. Existing Windows 10 analysis VMs under
Documents/Virtual Machines and the local Windows.iso (detected Windows 10 2004)
remain untouched; they are not clean/current qualification baselines.

The newly created dedicated VirtualBox VM is `panopticon-windows-validation`,
UUID `0bebee33-f9a3-462c-afa5-0df1f04e68d0`, under
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\vms`.
It has 4096 MiB RAM, four vCPUs, an 80 GiB dynamically allocated disk, EFI, emulated
TPM 2.0, NAT, no clipboard/drag-and-drop and read-only `panopticon-build` staging.
No existing VM registration, disks, snapshots or guest state was modified.

## Image and resources

The official [Microsoft Windows 11 Enterprise evaluation download page](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise)
publishes the English LTSC link with linkid 2289029. HTTPS redirects to Microsoft's
software-static.download.prss.microsoft.com image named
`26100.1742.240906-0331.ge_release_svc_refresh_CLIENT_LTSC_EVAL_x64FRE_en-us.iso`,
5,112,850,432 bytes. The owned download completed successfully and was finalized
without replacing an existing file. Its local SHA-256 is
`67CEC5865EAA037A72DDC633A717A10A2BED50778862267223DDB9C60EF5DA68`;
source/size/hash provenance is stored beside the ISO. It is evaluation media,
not a permanent Windows
license. Microsoft documents a 90-day evaluation; activation/registration and
expiry must be recorded. The current VerifyWindowsISO page lists 26H2 hashes,
not this LTSC image; those hashes must not be substituted. Record the final
local SHA-256 and download provenance; independent publisher-hash comparison is
unverified unless the exact matching publisher digest is obtained.

The user explicitly authorized concurrent operation with a 4 GiB/four-vCPU
Windows guest on 2026-10-06. The guest was started headless with
`Start -AllowMemoryPressure`; the installer progressed through its first stage
and displayed its impending restart. The VM remains running; the subsequent
framebuffer is black and Guest Additions reports not ready. VBox debug OS
detection reports WinNT, which alone does not prove installation completion.
Guest installation/login/Additions and qualification remain unverified.
The default `Start` workflow retains its 5120 MiB available-memory gate, with
an explicit override for authorized concurrent runs. It never stops another VM
or application. The host has an automatically managed page file, observed at
24,331 MiB allocated and 2,906 MiB used after VM startup. Page-file capacity
extends commit backing; it is not physical RAM or proof of sustained performance.
No additional ISO is requested from the user.

## Repeatable workflow

`tools/windows_validation_vm.ps1` operates only on the exact new VM UUID/name.
Its actions are Status, Diagnose, PrepareInstall, Start, Stage, Snapshot and Restore.
Diagnose captures two VM/storage-counter/host-memory observations 30 seconds
apart, a framebuffer and selected guest readiness properties, with SHA-256
evidence manifests. It excludes credentials and memory/register dumps. It does
not reset, stop, or claim that the guest is installed. Debugger `info clocks`
is deliberately excluded: this version logged `VERR_VM_THREAD_NOT_EMT` at
clock-query time, so those debugger clock values cannot independently establish
a guest TSC fault.
PrepareInstall uses generated dedicated guest passwords stored only in a
protected local credentials directory, and installs Guest Additions. Installation
auxiliary files contain credentials and stay outside Git in that protected
directory. Start is headless with a default resource gate and explicit override.
Stage requires a fresh Release
build and creates a distinct read-only package with SHA-256 manifest and a
Microsoft-signed VC++ runtime installer; debug CRT binaries are not redistributed.

Unattended installation is running. After it completes, confirm guest
OS/activation/update state and Guest Additions,
install current staged binaries and execute windows_guest_validation.ps1 as the
dedicated guest administrator. Copy the resulting ProgramData evidence out with
authenticated Guest Control. Local offline capture and command component tests
need no enrollment; future authenticated delivery/response runs need dedicated
test enrollment and a trusted Manager development CA reachable through NAT host
address 10.0.2.2. No insecure TLS exemption is a qualification result.

Cold snapshot `endpoint-clean-baseline` is taken only after OS/prerequisites and
baseline validation. Each coherent wave runs in a dedicated snapshot/clone;
export evidence before cold restore. A fresh installation snapshot is not a
validated baseline. Future scenarios progressively add privileged telemetry,
reboot/resume, cursor/log clearing, offline replay, PID reuse/target safety,
typed response, failed storage, source faults and stress/soak. Destructive
isolation/security-policy tests require disposable owned guests and evidence
export. No helper restores or powers off the Linux VM.

Current state is **running with four vCPUs/4096 MiB RAM; unattended Windows 11
installation completion unverified; Guest Additions not ready; guest tests and
qualified baseline snapshot pending**. VBox logs show repeated 60-second virtual
timer catch-up abandonment under this concurrent run; this is a resource/timing
qualification concern, not proof of a crashed VM. No reboot/reset was issued
because an observation timed out. The Linux VM remains untouched.
Guest scripts are prepared, not evidence that those tests have run. Host Windows
runtime/component evidence remains separately reported in VALIDATION.md.

## Installation recovery evidence, 2026-10-07

Owned diagnostics under
`C:\Users\Acer\Documents\Panopticon-Windows-Validation\diagnostics\run-dd4140dffe9842269886a1b78947447f`
retain identical storage counters at 19:43:50 and 19:44:21 UTC, a black
framebuffer, Guest Additions run level 0, and a running four-vCPU/4096 MiB guest.
Ctrl+Alt+Delete produced no visible response; Guest Control still refused with
Guest Additions unavailable, and `debugvm info bugcheck` reported no bug check.
A normal ACPI power-button request at 19:44:22 UTC did not stop the guest in the
subsequent observation. These observations establish unusable validation access;
they do not prove a Windows crash or its cause.

[Oracle's 7.2 troubleshooting documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Troubleshooting.html)
describes conflicts/poor performance with the host Hyper-V backend. This is a
possible environment contributor, not a diagnosis of this guest. Disabling host
security features or rebooting the shared host would affect other work and was
not performed. Linux remains untouched.

A live diagnostic snapshot named `install-stall-preserved-20261007-0119`
completed successfully, UUID `019f78a5-96dd-4e03-988c-b2962f65c084`. During its
live operation the initially empty saved-state file did not justify cancellation
or a second snapshot. This is an unqualified diagnostic snapshot, never an
endpoint baseline. After completion and exact owned-VM running-state verification,
one recovery reset was issued at 19:47:56 UTC. The guest returned to EFI Windows
boot-manager loading and the framebuffer displayed the boot splash. ResetCounter
is now 1. Guest login/Additions and endpoint validation remain unverified; do not
repeat resets just because a boot/readiness observation times out.

Post-reset diagnostics `diagnostics\run-1fa98df51f82418eb1ce1de1572df280`
show real storage activity: disk reads advanced from 101,311,488 to 285,601,792
bytes and writes from 13,312 to 48,895,488 bytes between 19:48:37 and 19:49:07
UTC. The framebuffer now shows a boot spinner. Guest Control still reports
Additions unavailable. This is verified boot activity, not successful login or
completion; continue observing this same guest without repeating recovery.
The subsequent framebuffer reached Windows setup's `Installing 0%` screen,
with its keep-powered-on/restart notice. This confirms installation resumed
past the previous black screen; setup completion remains pending.

The staged guest harness now defaults to native ETW and checks its dedicated
guest name plus elevation before installation or fixture mutation. Optional
`-ExerciseProcessLifecycle` launches an owned bounded ping process, retains its
PID plus native creation FILETIME, and checks one durable ETW stop against that
exact identity, native exit clock and exit code after two identical journal
readbacks. Native-stop absence fails the requested fixture rather than claiming
success from other telemetry. Partial component results survive a test timeout.
PowerShell syntax and host refusal were checked; actual guest execution remains
pending. Latest package: `staging\build-20261007-011626`.

Latest history wave package: `staging\build-20261007-013616`, containing fresh
schema-5 Release binaries and archive readback checks. Debug/Release validation
is recorded in [process history](PROCESS_HISTORY.md), not presented as guest
evidence. Setup subsequently displayed `Installing 42%`, then returned to a
black framebuffer. Diagnostics `run-92c27db317e34130ac4b21b06aa48a05` retain
identical disk counters over 30 seconds at 20:04:11/20:04:41 UTC. A subsequent
Ctrl+Alt+Delete again had no visible response, and no bug check was reported.
Both VMs remain running; no additional recovery reset was issued. The initial
recovery demonstrated setup progress, not a resolved virtualization problem.
Guest readiness and repeatable reboot/installation qualification remain open.
