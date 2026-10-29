# Windows Validation Status

Owner: Windows session (panopticon-agent, branch `demo/windows-validation`).
Channel: this file is the Windows → Mac status channel. Mac → Windows is `panopticon-manager/docs/demo/MAC_STATUS.md`.

Base: `origin/main` @ `7de7a97` (agent). Fallback agent binary: v0.3.0 @ `3339055`.

---

## Live environment (confirmed this session)

- Host: `LAPTOP-0P18IHB7` (VMware Workstation). `vmrun` available; 4 lab VMs powered on.
- Guest (Windows endpoint): `PANO-NEW-WIN-01`, VMnet10 `10.77.10.31`.
- Manager VM: `pano-new-mgr`, `10.77.10.10`. nginx on `:443` (TLS, lab CA), uvicorn on `127.0.0.1:8000`.
- Both `panopticon-manager.service` and `panopticon-console.service` are currently **active** on the manager VM.
- VM access tooling preserved outside the repo at `C:\PanopticonLab\tools-vm\` (survives branch switches).

---

## W0 — stop idle collector + disk assessment  ✅ done

- Idle local-collection agent (PID 3488) **stopped**; fail-safe service `PanopticonOfficer` confirmed **Stopped**. Nothing is collecting in the guest.
- Two prior local sessions saved to validated host gzips (not demo evidence; benign/idle training seed):
  - `collection-kit/data/raw/officer_lab_PANO-NEW-WIN-01_local-20261030.ndjson.gz` — 40,962 records
  - `collection-kit/data/raw/officer_lab_PANO-NEW-WIN-01_active.ndjson.gz` — 16,176 records
- Guest disk: freed 2.35 GB of logs/redundant raw → ~15.25 GB free at assessment.
- **Spool preserved.** The 16.5 GB guest spool (`C:\PanoValidation\officer-service\spool\journal.db`) is being archived off-guest to `C:\PanopticonLab\Archives\journal-overnight-20261030.db`. It is **NOT deleted** and will not be deleted without the owner's explicit approval. (Note: the spool DB is incompressible — already-encoded record blobs — so the archive is a raw copy.)

## W1 — manager /srv + DB  ⚠️ BLOCKER FOUND (environmental, G6)

- **`/srv/panopticon-data` is a dedicated 40 GB volume (`/dev/sdb`, ext4) that is 100% full, 0 bytes free.**
  - `panopticon.db` = 39 GB, `panopticon.db-wal` = 1.1 GB, `panopticon.db-shm` = 2.1 MB (mtime Oct 28–29).
  - The manager process holds this DB open (uvicorn pid on `:8000`). With the volume full, SQLite cannot write new records → ingest returns 500 (the overnight disk-full condition, still present).
- **Literal W1 "move the DB aside" is not possible as written:** nothing has room for a 39 GB file. The root fs (`/`, `/dev/sda1`) has only ~36 GB free (< 39 GB), and the DB's own volume is full.
- This 39 GB DB contains the Oct 27–28 live run (genuine demo evidence). Per plan it must be preserved, not deleted — so a decision is required (archive-off + delete to reclaim the dedicated volume, vs. deploy the fresh demo DB on the root fs and leave the full volume untouched). Pending owner decision; sequenced into W4 (requires stopping the systemd unit first).
- VM snapshots: not yet taken (pending owner approval — snapshotting may interact with external VMware automation).

## W2 — build agent from `origin/main` (`7de7a97`)  🔄 building (download approved)

- Owner approved the vcpkg download. Building x64-windows out-of-tree at `C:\PanopticonLab\build-officer-x64` via the VS 2026 (v18) x64 Developer shell (cmake + ninja from the VS CMake component).
- `vcpkg install` completed (nlohmann-json, tinyxml2 built OK); agent compile in progress.
- sha256 of the resulting `officer-agent.exe` will be recorded here on completion.
- Fallback ready: v0.3.0 `3339055` binary in the guest (`C:\PanoValidation\wave6-20261027\agent\officer-agent.exe`), which previously delivered live over TLS.

## W3 — Sysmon EID 1 / 3 / 13  ✅ done

- Loaded config present; generated and verified in the Sysmon operational log (last 3 min):
  - EID 1 (process create): 8
  - EID 3 (network connect): 31
  - EID 13 (registry value set): 10
- EID 13 (required for DET-PERS-001) confirmed emitting.

---

## Blockers to report to Mac session

1. **G6 realized (environmental):** manager DB volume `/dev/sdb` is 100% full. Any live demo needs the fresh demo DB on a volume with room. `demo_up.sh --fresh --state-dir <dir>` should target a path NOT on the full `/dev/sdb` (e.g., on root fs), or the full volume must be reclaimed first. `demo_check.sh` free-disk reporting is essential.

## Owner decisions (2026-10-30)

- **W2:** build from `7de7a97` (download approved). v0.3.0 `3339055` is the fallback.
- **Manager DB (W4):** archive the 39 GB evidence DB off the VM, then delete it to reclaim `/dev/sdb`, then start the fresh demo DB there. Executes at W4 after stopping the systemd unit.
- **Snapshots:** none.
- **Guest spool:** preserve; archive off-guest; not deleted without a further explicit OK.

## W6 — demo scripts (prep, not yet exercised)

- `tools/demo/demo-triggers.ps1` — drafted. The §6 trigger harness (benign control + 5 rule-mapped steps), ISO-8601 UTC timestamps for time-to-alert.
- `tools/demo/demo-up.ps1` — scaffold. One-command bring-up (ssh `demo_up.sh` → token to guest → fresh-enroll agent → `demo_check.sh` green → open console). Output parsing (step 2) and exact agent flags (step 4) are marked `TODO(mac-contract)` pending `demo_up.sh` on `demo/live-integration`.

## W4 — deploy manager + console  ✅ done

- Deployed `demo/live-integration`: manager @ `398442d` (submodules pinned: eyedetect `9697e6b` = engine, response_engine `83b8a46`), console @ `86b01c9`. VM-local manager patches stashed (`git stash` on the VM, recoverable).
- Stopped `panopticon-manager.service` + `panopticon-console.service` (freed 8000/8787).
- `tools/demo_up.sh --fresh --bind 127.0.0.1:8000 --state-dir /home/pano/demo-state --python /home/pano/manager-venv/bin/python` → **green, exit 0** in ~seconds: Manager schema 31, **74 rules, detection worker alive**, fresh 1 MB DB on root fs (37.7 GB free), console up, 0 agents/records/alerts.
- nginx still fronts `:443` → `127.0.0.1:8000`; `https://10.77.10.10/readyz` returns the fresh manager (`schema_version 31`).

### Notes for Mac
- `demo_up.sh` prints the agent `--manager-url` as `https://127.0.0.1:8000` (loopback). The real guest agent must use `https://10.77.10.10` (nginx→8000). Minor; just flagging.
- Console bound **loopback-only** (`127.0.0.1:8787`), not `0.0.0.0` — browser on the Windows host can't reach it directly over VMnet10. Will use an SSH `-L` forward (or a `--console-bind` flag if supported) for the on-stage view.

## W5 — fresh enrollment  🔄 in progress (build fix)

- Staged agent + `tinyxml2.dll` + 43-byte bootstrap token into guest `C:\pano\`; fresh spool, no identity.
- **Finding (build):** the first agent build (no `CMAKE_BUILD_TYPE`) linked the **Debug CRT** (`MSVCP140D.dll`, `VCRUNTIME140D.dll`, `ucrtbased.dll`) → `0xC0000135` on the guest (debug CRT is not redistributable). **Fix: build with `-DCMAKE_BUILD_TYPE=Release`.** Rebuilding now; release CRT deps confirmed present on the guest. (Runbook note for Mac: the agent must be a Release build.)

## W5 — fresh enrollment  ✅ done

- Release agent built (`-DCMAKE_BUILD_TYPE=Release`), sha256 `EF31DAD99FF7E53C302CF57C1FC03EC89D13FE2560C952B1518B06C3C143A6C1`, imports verified release CRT (no `D` suffix), `--help` exit 0, deployed to guest `C:\pano\` (SHA-matched).
- Launched with runbook args (`--source all --manager-url https://10.77.10.10 --enable-response --bootstrap-token-path … --identity-path … --keypair-path … --spool-directory C:\pano\spool-demo`).
- **Agent stays running; fresh enrollment succeeded** — identity + keypair persisted, 1 agent enrolled, delivering over trusted TLS (lab CA; no `--insecure-tls`).
- **Limitation:** ETW collector could not start (`StartTraceW: Insufficient system resources` — leftover ETW sessions). **Sysmon collector runs**, which supplies EID 1/3/13 used by all demo scenarios. (Side effect: no ETW/Sysmon duplicate process-start, so the duplicate-alert concern did not materialize this run.)

## W6/W7 — live end-to-end verification  ✅ pipeline PROVEN (3/5 positives + bonus correlation)

Telemetry: endpoint_records reached **done = 43,853+, failed = 0**; detection worker alive, 0 loop errors. Record inspected: canonical 1.0 `observation` / family `process` with `host_id`.

Verified alerts (persisted, retrieved via `GET /api/v1/alerts`, and shown in the console over VMnet10 with `X-Panopticon-Alert-Source: manager`):

| Trigger | Rule | Severity | MITRE | Time-to-alert | Evidence |
|---|---|---|---|---|---|
| whoami /priv | **DET-PROC-008** | medium | T1033 Discovery | ~1.5 s | `process.command_line = "…whoami.exe" /priv`, parent powershell.exe, matched_conditions ✓ |
| schtasks /create+/delete | **DET-PERS-002** | medium | — | ~1.5 s | host_id ✓ |
| cmdkey /list | **DET-CRED-003** | high | — | ~1.9 s | host_id ✓ |
| (correlation) | **CORR-RISK-001** | high | — | — | storyline risk |
| (correlation) | **PROV-CAMPAIGN** | medium | — | — | campaign |

Captures (no secrets) in `docs/demo/captures/`: `alerts-rehearsal-1.json`, `trigger-records-rehearsal-1.ndjson`.

### Remaining / blocked (environmental, needs host action)
- **DET-PROC-003 (certutil)** and **DET-PERS-001 (reg Run key)** triggers + the **benign control** have NOT been run yet, and **rehearsal #2** is pending.
- **Blocker:** after sustained use, 4 `python.exe` helper processes on the host wedged and hold the VMware guest-ops channel; any new `vmrun`/`guest.py` spawn is denied by the OS (`EPERM`/`Access is denied`), while `ssh`/`curl` to the manager still work. The fix is to kill the stuck PIDs and re-run the remaining triggers — but the automation classifier blocks process-kill, so this needs an explicit human action/authorization. Manager + console + agent remain up and healthy; no data lost.

## Acceptance status
- ✅ Release agent launches on guest · ✅ enrollment + identity persists · ✅ telemetry reaches manager · ✅ processing completes (0 failed) · ✅ ≥2 targeted scenarios verified (3) · ✅ alerts persisted + API-retrievable · ✅ dashboard reachable from presentation host + displays real alerts.
- ⏳ All five tested: 3/5 done; DET-PROC-003 + DET-PERS-001 pending the spawn-channel unblock · ⏳ benign control pending · ⏳ two consecutive rehearsals pending.

---

_Timings log (rehearsals) — to be filled at W7._
