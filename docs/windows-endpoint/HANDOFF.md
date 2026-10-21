# Windows endpoint engineering handoff

Updated: 2026-10-21

This handoff is for the next engineer continuing the Windows endpoint mission. The approved source plan is preserved verbatim in [FULL_SURFACE_ENGINEERING_PLAN.md](FULL_SURFACE_ENGINEERING_PLAN.md). The implementation remains incomplete; this handoff does not change the plan's A–AN scope or Definition of Done.

## Read these first

1. [Full Surface Engineering Plan](FULL_SURFACE_ENGINEERING_PLAN.md) — approved requirements, A–AN capability matrix and completion criteria.
2. [Capability matrix](CAPABILITY_MATRIX.md) — living implementation/gap ledger. Its current header says no domain is qualified complete; its last stated update is 2026-10-07.
3. [Validation ledger](VALIDATION.md) — evidence ledger. It contains later entries, including a 2026-10-09 native memory-region component wave. Reconcile this later evidence into the matrix as work proceeds; do not assume the matrix header is current.
4. [Windows VM workflow](WINDOWS_VM.md) — owned guest, installation, evidence, snapshots and validation procedures. Verify actual VM state before use.

The authoritative Windows endpoint repository is `panopticon-agent` inside the top-level Panopticon workspace. The implementation baseline before this documentation handoff is `d6afc2ff1bc1c98b6be50fc08d454699a3e924ed` (`feat: expand native Windows endpoint coverage`). This handoff adds documentation only.

## Direction and boundaries

- Make the Windows agent an excellent standalone sensor and enforcement endpoint. Use Windows-native semantics and sources such as ETW, Windows Event Log, USN, SCM and Windows APIs; retain OS-specific event bodies inside a coherent versioned common envelope.
- Preserve common identity, sequencing, provenance, process-instance, health/loss, command and result semantics. Do not force Linux event structures onto Windows.
- Sokhi is rebuilding the Detection Engine. Keep endpoint work decoupled from its current implementation; validate endpoint contracts without spending effort on broad integration scenarios.
- Keep low-latency/offline local prevention bounded to the EDR role. Fleet-wide detection and correlation belong in the Detection Engine; do not expand this into an antivirus product.
- Kernel signing, HLK, PPL and ELAM qualification are eventual gates for capabilities that require them. They must not stall user-mode endpoint progress. Report degraded, unavailable, disabled, unsupported and blind coverage accurately.
- Protect Claude's concurrent Linux work. Never reset, clean, revert, overwrite or stop another agent's work or VM. The user authorized concurrent Windows/Linux VM use with the Windows guest at 4 vCPU and 4 GiB; check the live state and the workflow before operating the guest, and do not change the Linux VM.

## Evidence and current completion boundary

The matrix and validation ledger document substantial native implementation, component tests, and selected successful guest runs across process, filesystem/USN, service, state, log and response-related areas. The validation ledger records fresh Debug and Release suites with 42 tests for the 2026-10-09 memory-region wave. That wave verifies bounded `VirtualQueryEx` metadata at the native component level; it does not read process contents or prove injection, and the ledger explicitly does not treat it as dedicated-guest endpoint-runtime qualification.

Use each ledger entry to distinguish implementation, component evidence, real-Windows guest evidence, and remaining qualification. Historical guest runs establish only their named scenarios. They do not establish full source coverage, all-OS compatibility, soak/chaos behavior, protected-target behavior, or completion of A–AN. The matrix's Definition of Done remains unmet; do not promote a capability based only on compilation, test counts or a successful demo.

## Continuation sequence

1. Read the plan's full Definition of Done, then compare every A–AN row with current code and the dated validation evidence. Update the living matrix where newer evidence is missing or a status is too broad.
2. Choose the next substantial capability wave from the plan, prioritizing foundational process-instance identity, provenance, durability/replay, loss accounting, host state, safe response target verification, and endpoint health/coverage while maintaining breadth across the remaining surface.
3. Implement a coherent end-to-end slice in the Windows agent, with fault/restart/idempotency behavior and meaningful tests. Preserve explicit unsupported and unverified states rather than fabricating coverage.
4. Run consolidated real-Windows validation through the owned-VM workflow when feasible. Record the exact guest/build, scenario, evidence location and hash, failures, and what the run does not prove. Never label component-only results as guest or E2E validation.
5. Update `CAPABILITY_MATRIX.md` and `VALIDATION.md` in the same engineering wave, then continue to the next major gap. Revisit contract or other-repository changes only when a concrete endpoint requirement needs them; do not weaken endpoint capability to fit the current Detection Engine.

For any change that needs privileged kernel components, document the qualification dependency and continue independent user-mode work. Completion requires evidence across the plan's complete capability surface and explicit satisfaction of its Definition of Done, not merely a working VM or green test suite.
