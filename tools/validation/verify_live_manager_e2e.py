"""Live Officer agent -> Manager end-to-end check on this Windows host.

Starts an owned Manager (temporary DB, self-signed TLS on 127.0.0.1) and the real
officer-agent.exe with a one-shot bootstrap token, generates benign owned activity,
then verifies from the Manager's own database:

1. enrollment, canonical ingestion and durable persistence of live records;
2. a live process start for an owned process with native_exact identity;
3. detection on live canonical records (whoami /priv -> DET-PROC-008);
4. a schema-2 KILL_PROCESS built from the Manager-held record of an owned benign
   process is dispatched, executed on that exact instance and its v2 result
   accepted and retained.

Requires an elevated session (ETW/Sysmon). Uses only test-owned processes and
files, an isolated spool/identity, and never sends isolation or file actions.
Writes a JSON summary to --evidence when given.

    <manager-venv>/python tools/validation/verify_live_manager_e2e.py [--agent PATH] [--manager DIR] [--evidence FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AGENT_ROOT = Path(__file__).resolve().parents[2]
# Sibling Manager checkout (its own venv supplies uvicorn/fastapi); override with --manager.
ROOT = AGENT_ROOT.parent / "panopticon-manager"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def certificate(scratch: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated live agent check")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = scratch / "key.pem", scratch / "cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(predicate, seconds: float, what: str, interval: float = 1.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}")


def query(db: Path, sql: str, params=()):
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, default=Path(os.environ.get(
        "OFFICER_BUILD_DIR", str(AGENT_ROOT / "build-officer-x64"))) / "officer-agent.exe")
    parser.add_argument("--manager", type=Path, default=ROOT)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory")
    parser.add_argument("--trusted-tls", action="store_true",
        help="test VM only: trust this run's own test CA in LocalMachine Root for the run, let the "
             "agent enroll itself and require the full command round trip")
    options = parser.parse_args()
    if options.trusted_tls and os.environ.get("PANO_ALLOW_TRUST_STORE_CHANGE") != "1":
        raise SystemExit("--trusted-tls changes the machine trust store; set "
                         "PANO_ALLOW_TRUST_STORE_CHANGE=1 only on a disposable test VM")
    manager_root = options.manager.resolve()
    if not options.agent.is_file():
        raise SystemExit(f"officer-agent.exe not found at {options.agent}")

    scratch = Path(tempfile.mkdtemp(prefix="panopticon-live-agent-"))
    key_path, cert_path = certificate(scratch)
    port = free_port()
    db = scratch / "manager.db"
    command_token = uuid4().hex
    environment = dict(os.environ, PANOPTICON_DB_PATH=str(db),
        PANOPTICON_ALERTS_PATH=str(scratch / "alerts.ndjson"),
        PANOPTICON_ENROLLMENT_TOKEN="live-bootstrap-" + uuid4().hex,
        PANOPTICON_COMMAND_TOKEN=command_token)
    token_file = scratch / "bootstrap.token"
    token_file.write_text(environment["PANOPTICON_ENROLLMENT_TOKEN"], encoding="ascii")
    summary: dict = {"agent": str(options.agent), "agent_sha256": hashlib.sha256(
        options.agent.read_bytes()).hexdigest(), "started_utc": datetime.now(timezone.utc).isoformat()}
    server_log = open(scratch / "manager.log", "wb")
    agent_out, agent_err = open(scratch / "agent.stdout", "wb"), open(scratch / "agent.stderr", "wb")
    server = agent = target = None
    trusted_serial = None
    try:
        if options.trusted_tls:
            serial = format(x509.load_pem_x509_certificate(cert_path.read_bytes()).serial_number, "x")
            subprocess.run(["certutil", "-addstore", "-f", "Root", str(cert_path)], check=True,
                           capture_output=True, creationflags=NO_WINDOW)
            trusted_serial = serial
            summary["trust"] = "run-owned test CA added to LocalMachine Root for this run"
        server = subprocess.Popen([sys.executable, "-m", "uvicorn", "manager.app:app", "--host",
            "127.0.0.1", "--port", str(port), "--ssl-keyfile", str(key_path), "--ssl-certfile",
            str(cert_path)], cwd=manager_root, env=environment, stdout=server_log, stderr=server_log,
            creationflags=NO_WINDOW)
        base = f"https://127.0.0.1:{port}"
        with httpx.Client(base_url=base, verify=False, timeout=5) as client:
            wait_for(lambda: server.poll() is None and _healthy(client), 30, "Manager start")
            if options.trusted_tls:
                # The agent enrolls itself (bootstrap token) over verified TLS.
                transport = ["--bootstrap-token-path", str(token_file)]
                summary["enrollment"] = "agent_self_enrolled_over_verified_tls"
            else:
                # Real enrollment (challenge + P-256 proof of possession) on the agent's
                # behalf: the agent's own enrollment/response channel always verifies TLS
                # and this host's trust store is not modified for a self-signed Manager.
                sys.path.insert(0, str(manager_root))
                from tests.conftest import enroll_test_agent
                agent_name, host_name = "live-agent-" + uuid4().hex[:8], "live-host-" + uuid4().hex[:8]
                enrolled = enroll_test_agent(client, agent_name, host_name,
                    token=environment["PANOPTICON_ENROLLMENT_TOKEN"])
                enrolled.raise_for_status()
                identity_lines = [agent_name, host_name, enrolled.json()["access_token"]]
                (scratch / "identity").write_text("\n".join(identity_lines) + "\n", encoding="ascii")
                transport = ["--insecure-tls"]
                summary["enrollment"] = "harness_enrolled_via_real_api_identity_provisioned"
            agent = subprocess.Popen([str(options.agent), "--source", "all", "--manager-url", base,
                *transport, "--enable-response", "--identity-path", str(scratch / "identity"),
                "--spool-directory", str(scratch / "spool"),
                "--keypair-path", str(scratch / "agent.key")],
                stdout=agent_out, stderr=agent_err, cwd=scratch,  # relative defaults stay owned
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            enrolled = wait_for(lambda: query(db, "SELECT agent_id, host_id FROM enrolled_agents"),
                90, "agent enrollment")[0]
            agent_id = enrolled["agent_id"]
            summary["agent_id"], summary["host_id"] = agent_id, enrolled["host_id"]
            # Collectors subscribe after enrollment; give live sources time to start.
            time.sleep(15)

            marker = "panopticon-live-" + uuid4().hex[:12]
            subprocess.run(["cmd.exe", "/c", f"whoami /priv > nul & echo {marker} > nul"],
                check=True, creationflags=NO_WINDOW)
            (scratch / f"{marker}.txt").write_text(marker, encoding="ascii")
            target = subprocess.Popen(["ping.exe", "-n", "300", "127.0.0.1"],
                stdout=subprocess.DEVNULL, creationflags=NO_WINDOW)
            summary["marker"], summary["target_pid"] = marker, target.pid

            live = wait_for(lambda: query(db,
                "SELECT raw_json FROM endpoint_records WHERE kind='observation' AND category='process' "
                "AND raw_json LIKE ?", (f"%{marker}%",)), 120, "owned live process start")
            marked = json.loads(live[0]["raw_json"])
            summary["marked_process"] = {"record_id": marked["record_id"],
                "provenance": marked["provenance"]["kind"] + ":" + marked["provenance"]["provider"],
                "resolution": marked["subject"]["resolution"]}

            def target_record():
                rows = query(db, "SELECT raw_json FROM endpoint_records WHERE kind='observation' "
                    "AND category='process'")
                for row in rows:
                    record = json.loads(row["raw_json"])
                    subject = record.get("subject") or {}
                    if subject.get("observed_pid") == target.pid and subject.get("resolution") == "native_exact":
                        return record
                return None
            held = wait_for(target_record, 120, "native_exact record of the owned target")
            summary["target_record"] = {"record_id": held["record_id"],
                "native_creation_ticks": held["subject"]["native_creation_ticks"],
                "boot_id": held["endpoint"]["boot_id"]}

            detected = wait_for(lambda: query(db, "SELECT alert_id, rule_id FROM alerts WHERE "
                "agent_id=? AND rule_id='DET-PROC-008'", (agent_id,)), 120, "DET-PROC-008 alert",
                interval=2)
            summary["detection"] = [dict(row) for row in detected][:3]

            command_id = "live-kill-" + uuid4().hex[:12]
            command = {"command_id": command_id, "schema_version": "2", "agent_id": agent_id,
                "action": "KILL_PROCESS", "expires_at": (datetime.now(timezone.utc)
                + timedelta(minutes=5)).isoformat(), "target": {"pid": target.pid,
                "start_time_ticks": held["subject"]["native_creation_ticks"],
                "boot_id": held["endpoint"]["boot_id"]}}
            response = client.post("/api/v1/commands", json=command,
                headers={"X-Panopticon-Command-Token": command_token})
            response.raise_for_status()
            try:
                final = wait_for(lambda: query(db, "SELECT lifecycle_state FROM commands WHERE "
                    "command_id=? AND lifecycle_state IN ('SUCCEEDED','FAILED','REJECTED',"
                    "'INDETERMINATE','EXPIRED')", (command_id,)), 60, "command result")[0]["lifecycle_state"]
            except TimeoutError:
                final = query(db, "SELECT lifecycle_state FROM commands WHERE command_id=?",
                    (command_id,))[0]["lifecycle_state"]
            receipt = query(db, "SELECT raw_json FROM command_result_receipts WHERE command_id=?",
                (command_id,))
            summary["command"] = {"command_id": command_id, "lifecycle_state": final,
                "result": json.loads(receipt[0]["raw_json"]) if receipt else None,
                "target_exited": target.poll() is not None}
            if final == "SUCCEEDED":
                summary["command"]["target_exited"] = bool(
                    wait_for(lambda: target.poll() is not None, 20, "target exit"))
            if final in ("PENDING", "AUTHORIZED") and not options.trusted_tls:
                summary["command"]["blocked"] = ("agent response channel verifies TLS and the "
                    "self-signed test Manager is untrusted on this host; validate on the VM")

            counts = query(db, "SELECT kind, category, COUNT(*) AS n FROM endpoint_records "
                "GROUP BY kind, category ORDER BY n DESC")
            summary["records"] = {f"{row['kind']}/{row['category']}": row["n"] for row in counts}
            summary["record_total"] = sum(summary["records"].values())
            states = query(db, "SELECT detect_state, COUNT(*) AS n FROM endpoint_records "
                "GROUP BY detect_state")
            summary["detect_states"] = {row["detect_state"]: row["n"] for row in states}
        # Ingest/persistence/attribution/detection are this host's gate; the command
        # round trip is reported separately (it needs a trusted Manager certificate).
        summary["passed"] = (summary["marked_process"]["resolution"] in ("native_exact", "source_scoped")
            and bool(summary["detection"]) and summary["record_total"] > 0)
        if options.trusted_tls:
            summary["passed"] = summary["passed"] and (
                summary["command"]["lifecycle_state"] == "SUCCEEDED"
                and summary["command"]["target_exited"] is True)
        return 0 if summary["passed"] else 1
    except Exception as error:
        summary["passed"] = False
        summary["error"] = f"{type(error).__name__}: {error}"
        return 1
    finally:
        if agent is not None and agent.poll() is None:
            agent.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                agent.wait(60)
                summary["agent_exit"] = agent.returncode
            except subprocess.TimeoutExpired:
                agent.kill()
                summary["agent_exit"] = "killed_after_60s"
        if trusted_serial:
            removed = subprocess.run(["certutil", "-delstore", "Root", trusted_serial],
                                     capture_output=True, creationflags=NO_WINDOW)
            summary["trust_removed"] = removed.returncode == 0
        if target is not None and target.poll() is None:
            target.kill()
        if server is not None:
            server.terminate()
            server.wait(15)
        for handle in (server_log, agent_out, agent_err):
            handle.close()
        summary["agent_stderr_tail"] = (scratch / "agent.stderr").read_text(
            encoding="utf-8", errors="replace")[-1500:]
        summary["scratch"] = str(scratch)
        text = json.dumps(summary, indent=2, default=str)
        print(text)
        if options.evidence:
            options.evidence.write_text(text + "\n", encoding="utf-8")


def _healthy(client: httpx.Client) -> bool:
    try:
        return client.get("/healthz").status_code == 200
    except httpx.HTTPError:
        return False


if __name__ == "__main__":
    sys.exit(main())
