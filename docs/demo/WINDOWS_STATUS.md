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

## W2 — build agent from `origin/main` (`7de7a97`)  ⏸ blocked on download approval

- Build toolchain is **not on PATH** on the host: `cmake`, `ninja`, `cl.exe` all missing from the shell. VS18 vcpkg toolchain file is present.
- A clean build needs a VS Developer environment + `vcpkg install` (downloads `nlohmann-json`, `tinyxml2`) → pending owner approval to download.
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

## Waiting on Mac

- No `demo/live-integration` branch or `MAC_STATUS.md` on origin yet. W4+ (deploy "ready `<sha>`") is correctly blocked until the Mac session publishes it.

---

_Timings log (rehearsals) — to be filled at W7._
