# Officer to the deployed Manager over VMnet10

This scenario uses `PANO-NEW-WIN-01` and the regular Manager service on Linux
`PANO-NEW-MGR`, at `https://10.77.10.10`. It never starts a Windows-local Manager.
No detection rule or synthetic telemetry is used as the pass gate.

## Prerequisites

Windows must reach the desktop, with VMware Tools, Sysmon, Python dependencies,
and the tested Officer binary plus its DLLs available. If firmware changes cause
BitLocker recovery, the operator must unlock the guest with the matching recovery
key. VMware's four encryption settings must remain enabled for its existing TPM.
Do not clear the TPM or replace the encrypted disk to get past this gate.

Configure the dedicated Windows VMnet10 adapter with
`tools/validation/vm/configure_manager_link.ps1`. Its default MAC is recorded from
this test VM's VMX; the adapter is assigned `10.77.10.31/24` without a default
gateway, leaving NAT on the other adapter. The script refuses another preexisting
static address and verifies port 443 using the VMnet10 source address.

Manager must run the coordinated integration revision with verified HTTPS. The
existing lab certificate includes IP SAN `10.77.10.10`. The harness imports only
that existing lab CA in the Windows test VM; host trust is unchanged. Manager's
existing nginx listener permits VMnet10. No broad firewall relaxation is required.

## Deployed lab storage

The original 40-GiB root disk filled with historical telemetry. VMware's resize
operation could not complete with the host's available scratch space. A separate
8-GiB data disk is mounted at `/srv/panopticon-data`. The complete original database
remains at `/var/lib/panopticon-manager/panopticon.db` with its original historical
events and endpoint records. It was not deleted or copied in full.

The active database is `/srv/panopticon-data/manager/panopticon.db`. Enrollment and
command state were copied and verified before migration to schema 18. Historical
telemetry stays in the original archive, so active counts exclude it. Manager's
systemd override requires the data mount, keeps existing private credentials, and
selects the deployed source at `/home/pano/panopticon-manager-wave6`. All three
existing enrollments were preserved; no Linux endpoint VM was reconfigured.

## Run

Run on the Windows host with access to the private lab SSH key and VMware guest
credentials. The `--agent` path is inside the Windows guest. Example:

```powershell
python tools/validation/verify_cross_vm_manager_e2e.py `
  --manager 10.77.10.10 `
  --database /srv/panopticon-data/manager/panopticon.db `
  --agent C:\PanoValidation\wave6-20261027\agent\officer-agent.exe `
  --evidence docs/windows-endpoint/evidence/20261027-cross-vm/summary.json
```

The host harness launches `vm/cross_vm_probe.py` in the guest. Officer self-enrolls
over its verified-TLS channel, uploads real process/file/system activity using a
dedicated identity and spool, and performs the actual freshness challenge. A held
test-owned ping.exe is correlated with Manager's exact boot/creation identity.
Only that process is authorized for KILL_PROCESS. The result must validate against
the current schema, be retained in the remote database, and show SUCCEEDED with
completion observed. The harness also requires persisted capture-age proofs and
checks nginx request statuses for HTTP 422. Agent shutdown and target exit are
verified before reporting success.

Evidence records both VM addresses, Manager hostname/revision/database, TLS
certificate and agent binary hashes, record counts, exact target identity and
the retained schema-2 result. Credentials and keys are never evidence. A failure
or a blocked BitLocker boot must not be documented as Cross-VM E2E Verified.
