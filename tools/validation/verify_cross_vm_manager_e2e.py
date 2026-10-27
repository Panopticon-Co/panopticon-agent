"""Real Officer -> deployed Linux Manager check over VMnet10.

Run on the Windows lab host with VMware guest access and SSH administration of
the Manager. The regular Manager service/database and HTTPS listener must already
run the recorded integration revision. No loopback Manager, synthetic records,
TLS bypass, or detection-rule pass gate is used. Secrets stay in the private lab
Keys directory and are never exported as evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import jsonschema


def wait_for(function, seconds: int, description: str):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = function()
        if value:
            return value
        time.sleep(3)
    raise TimeoutError(description)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager", default="10.77.10.10")
    parser.add_argument("--ssh-user", default="pano")
    parser.add_argument("--database", default="/var/lib/panopticon-manager/panopticon.db")
    parser.add_argument("--ssh-key", type=Path, default=Path("C:/PanopticonLab/Keys/lab_ed25519"))
    parser.add_argument("--keys", type=Path, default=Path("C:/PanopticonLab/Keys"))
    parser.add_argument("--guest-work", default=r"C:\PanoValidation\wave6-cross-vm")
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("guest", Path(__file__).parent / "vm/guest.py")
    guest = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guest)
    private = args.keys / ("cross-vm-" + uuid4().hex[:12])
    private.mkdir()
    run_id = uuid4().hex
    summary = {"started_utc": datetime.now(timezone.utc).isoformat(),
               "manager_url": f"https://{args.manager}", "run_id": run_id, "passed": False,
               "scenario": "cross_vm_live_transport", "guest_work": args.guest_work}
    ssh = ["ssh", "-i", str(args.ssh_key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           f"{args.ssh_user}@{args.manager}"]

    def remote(code):
        response = subprocess.run(ssh + ["sudo -n python3 -"], input=code,
                                  capture_output=True, text=True, timeout=90, check=True)
        return json.loads(response.stdout)

    def database(body):
        return remote("import sqlite3,json\n"
                      f"c=sqlite3.connect({'file:' + args.database + '?mode=ro'!r},"
                      "uri=True,timeout=15)\nc.row_factory=sqlite3.Row\n" + body)

    def probe_status():
        status = private / "guest-status.json"
        try:
            guest.get(args.guest_work + r"\probe-status.json", str(status))
        except RuntimeError:
            return None
        value = json.loads(status.read_text(encoding="utf-8"))
        if value.get("run_id") != run_id:
            return None
        if value.get("error"):
            raise RuntimeError(value["error"])
        return value if value.get("ready") else None

    launched = False
    try:
        credentials = remote(
            "import json,pathlib\n"
            "e=dict(line.split('=',1) for line in pathlib.Path("
            "'/etc/panopticon-manager/manager.env').read_text().splitlines() "
            "if '=' in line and not line.startswith('#'))\n"
            "print(json.dumps({k:e[k] for k in ['PANOPTICON_ENROLLMENT_TOKEN',"
            "'PANOPTICON_COMMAND_TOKEN']}))\n"
        )
        certificate = subprocess.run(ssh + [
            "sudo -n cat /etc/panopticon-manager/tls/ca.crt"
        ], capture_output=True, check=True).stdout
        ca = private / "manager-ca.crt"
        ca.write_bytes(certificate)
        bootstrap = private / "bootstrap.token"
        bootstrap.write_text(credentials["PANOPTICON_ENROLLMENT_TOKEN"], encoding="ascii")
        summary["manager_identity"] = remote(
            "import json,socket,pathlib\n"
            "print(json.dumps({'hostname':socket.gethostname(),"
            f"'database':{args.database!r},"
            "'deployment':pathlib.Path('/home/pano/panopticon-manager-wave6/REVISION').read_text()"
            " .strip()}))\n"
        )
        access_offset = remote(
            "import json,os\nprint(json.dumps(os.path.getsize('/var/log/nginx/access.log')))"
        )
        if summary["manager_identity"]["hostname"].lower() != "pano-new-mgr":
            raise RuntimeError("SSH destination is not PANO-NEW-MGR")
        guest_ca = args.guest_work + r"\manager-ca.crt"
        guest_bootstrap = args.guest_work + r"\bootstrap.token"
        guest_probe = args.guest_work + r"\cross_vm_probe.py"
        code, output = guest.ps(
            f"New-Item -ItemType Directory -Path '{args.guest_work}' -Force | Out-Null\n"
            f"icacls '{args.guest_work}' /inheritance:r /grant:r "
            "'*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null\n"
            "if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict guest credential directory' }"
        )
        if code:
            raise RuntimeError(output)
        guest.put(str(ca), guest_ca)
        guest.put(str(bootstrap), guest_bootstrap)
        guest.put(str(Path(__file__).parent / "vm/cross_vm_probe.py"), guest_probe)
        # Trust only the existing lab CA, inside the test VM. Keep it for the
        # endpoint's recorded remote-Manager configuration; host trust is unchanged.
        code, output = guest.ps(
            f"Import-Certificate -FilePath '{guest_ca}' -CertStoreLocation "
            "Cert:\\LocalMachine\\Root | Select-Object Thumbprint | ConvertTo-Json -Compress"
        )
        if code:
            raise RuntimeError(output)
        summary["guest_ca_import"] = output.strip()
        context = ssl.create_default_context(cafile=str(ca))
        with httpx.Client(base_url=summary["manager_url"], verify=context, timeout=20) as client:
            client.get("/readyz").raise_for_status()
            script = (
                "$ErrorActionPreference='Stop'\n"
                "Start-Process -FilePath 'C:\\Program Files\\Python312\\python.exe' "
                f"-ArgumentList @('{guest_probe}','--agent','{args.agent}',"
                f"'--manager-url','{summary['manager_url']}','--ca','{guest_ca}',"
                f"'--bootstrap-token','{guest_bootstrap}','--work','{args.guest_work}',"
                f"'--run-id','{run_id}') "
                "-WindowStyle Hidden\n"
            )
            code, output = guest.ps(script)
            if code:
                raise RuntimeError(output)
            launched = True
            status = wait_for(probe_status, 150, "guest did not enroll and start owned activity")
            summary["endpoint"] = status
            agent_id = status["agent_id"]
            if status["tls"]["peer"] != args.manager or status["tls"]["local"] == args.manager:
                raise RuntimeError("guest TLS connection did not use separate VM addresses")

            def target_record():
                rows = database(
                    "rows=c.execute('SELECT raw_json FROM endpoint_records WHERE agent_id=? "
                    "AND kind=? AND category=?',"
                    f"({agent_id!r},'observation','process')).fetchall()\n"
                    "print(json.dumps([json.loads(r[0]) for r in rows]))\n"
                )
                return next((record for record in rows if
                             (record.get("subject") or {}).get("observed_pid") == status["target_pid"]
                             and record["subject"]["resolution"] == "native_exact"), None)

            target = wait_for(target_record, 150, "owned native-exact process did not reach Manager")
            summary["target_record"] = target
            command_id = "cross-vm-kill-" + uuid4().hex[:12]
            command = {"schema_version": "2", "command_id": command_id, "agent_id": agent_id,
                       "correlation_id": "cross-vm-" + uuid4().hex,
                       "action": "KILL_PROCESS", "expires_at": (
                           datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                       "target": {"pid": status["target_pid"],
                                  "boot_id": target["subject"]["boot_id"],
                                  "start_time_ticks": target["subject"]["native_creation_ticks"]}}
            queued = client.post("/api/v1/commands", json=command, headers={
                "X-Panopticon-Command-Token": credentials["PANOPTICON_COMMAND_TOKEN"]})
            queued.raise_for_status()
            summary["command"] = command

            def receipt():
                rows = database(
                    "print(json.dumps([dict(r) for r in c.execute("
                    "'SELECT raw_json FROM command_result_receipts WHERE command_id=?',"
                    f"({command_id!r},))]))\n"
                )
                return json.loads(rows[0]["raw_json"]) if rows else None

            result = wait_for(receipt, 100, "native result was not retained by remote Manager")
            schema = json.loads((root.parent / "panopticon-contracts/schema/command_result.schema.json")
                                .read_text(encoding="utf-8"))
            jsonschema.validate(result, schema)
            summary["result"] = result
            if result["outcome"] != "succeeded" or not result["execution"]["completion_observed"]:
                raise RuntimeError("owned termination did not complete successfully")

            def telemetry_counts():
                counts = database(
                    "print(json.dumps([dict(r) for r in c.execute("
                    "'SELECT kind,category,COUNT(*) AS n FROM endpoint_records WHERE agent_id=? "
                    f"GROUP BY kind,category',({agent_id!r},))]))\n"
                )
                if (any(r["kind"] == "state" for r in counts)
                        and any(r["category"] == "file" for r in counts)):
                    return counts
                return None

            summary["records"] = wait_for(telemetry_counts, 90, "live file/system records missing")
            summary["record_total"] = sum(row["n"] for row in summary["records"])
            summary["capture_age_records"] = database(
                "print(json.dumps(c.execute('SELECT COUNT(*) FROM endpoint_capture_age "
                f"WHERE agent_id=?',({agent_id!r},)).fetchone()[0]))\n"
            )
            if not summary["capture_age_records"]:
                raise RuntimeError("production uploader did not persist freshness-proven records")
            summary["lifecycle_state"] = database(
                "print(json.dumps(c.execute('SELECT lifecycle_state FROM commands WHERE command_id=?',"
                f"({command_id!r},)).fetchone()[0]))\n"
            )
            summary["http_statuses"] = remote(
                "import json,re,collections\ncounts=collections.Counter()\n"
                "with open('/var/log/nginx/access.log') as f:\n"
                f" f.seek({access_offset})\n"
                " for line in f:\n"
                f"  if not line.startswith({status['tls']['local']!r}+' '): continue\n"
                "  m=re.search(r'\"(?:GET|POST) ([^ ]+) HTTP/[^\"]+\" (\\d{3})',line)\n"
                "  if m: counts[(m[1],m[2])]+=1\n"
                "print(json.dumps([{'path':p,'status':int(s),'count':n} "
                "for (p,s),n in sorted(counts.items())]))\n"
            )
            if any(row["status"] == 422 for row in summary["http_statuses"]):
                raise RuntimeError("Manager returned HTTP 422 to the live endpoint")
            if not any(row["path"] == "/api/v2/endpoint/freshness-challenge"
                       and row["status"] == 200 for row in summary["http_statuses"]):
                raise RuntimeError("production freshness challenge success was not observed")
            summary["passed"] = summary["lifecycle_state"] == "SUCCEEDED"
    except (OSError, RuntimeError, ValueError, httpx.HTTPError,
            subprocess.SubprocessError, jsonschema.ValidationError) as error:
        summary["error"] = f"{type(error).__name__}: {error}"
    finally:
        if launched:
            stop = private / "stop"
            stop.write_text("stop", encoding="ascii")
            try:
                guest.put(str(stop), args.guest_work + r"\stop")
                final = wait_for(lambda: (s if (s := probe_status()) and s.get("finished") else None),
                                 80, "guest cleanup did not finish")
                summary["endpoint_final"] = final
                summary["passed"] = summary["passed"] and final.get("passed", False)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                summary["cleanup_error"] = str(error)
                summary["passed"] = False
        # Keep the endpoint identity/spool and lab CA for reproducible remote use,
        # but retire this run's copies of the bootstrap credential.
        try:
            code, output = guest.ps(
                f"$tokenFile = '{args.guest_work}\\bootstrap.token'\n"
                "if (Test-Path -LiteralPath $tokenFile) { "
                "Remove-Item -LiteralPath $tokenFile -ErrorAction Stop }\n"
                "@{bootstrap_present=(Test-Path -LiteralPath $tokenFile)} | ConvertTo-Json -Compress"
            )
            if code or json.loads(output)["bootstrap_present"]:
                raise RuntimeError("guest bootstrap credential cleanup did not complete")
            summary["bootstrap_removed"] = True
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            summary["credential_cleanup_error"] = str(error)
            summary["passed"] = False
        (private / "bootstrap.token").unlink(missing_ok=True)
        summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(summary, indent=2) + "\n",
                                 encoding="utf-8", newline="\n")
        print(json.dumps({k: summary[k] for k in ("passed", "record_total", "error")
                          if k in summary}))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
