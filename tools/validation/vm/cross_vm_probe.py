"""Guest half of the live cross-VM transport check; runs no Manager locally.

Uses a dedicated identity/spool and a held, test-owned ping.exe. The host harness
reads Manager's database and authorizes termination of this exact process only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx


def save(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--manager-url", required=True)
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--bootstrap-token", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    parsed = urlparse(args.manager_url)
    if parsed.scheme != "https" or parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        parser.error("a remote HTTPS Manager is required")
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    files = work / "owned-files"
    files.mkdir(exist_ok=True)
    status_path = work / "probe-status.json"
    stop = work / "stop"
    # Only the owned stop marker from a previous invocation is reset.
    stop.unlink(missing_ok=True)
    result = {"manager_url": args.manager_url, "passed": False,
              "agent_sha256": hashlib.sha256(args.agent.read_bytes()).hexdigest()}
    agent = target = None
    stdout = (work / "agent.stdout").open("wb")
    stderr = (work / "agent.stderr").open("wb")
    try:
        context = ssl.create_default_context(cafile=str(args.ca))
        with (
            socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as raw,
            context.wrap_socket(raw, server_hostname=parsed.hostname) as tls,
        ):
            result["tls"] = {"version": tls.version(), "cipher": tls.cipher()[0],
                             "peer": tls.getpeername()[0], "local": tls.getsockname()[0],
                             "server_certificate_sha256": hashlib.sha256(
                                 tls.getpeercert(binary_form=True)).hexdigest()}
        with httpx.Client(base_url=args.manager_url, verify=context, timeout=15) as client:
            readiness = client.get("/readyz")
            readiness.raise_for_status()
            result["readyz"] = readiness.json()
            command = [str(args.agent), "--source", "all", "--manager-url", args.manager_url,
                       "--enable-response", "--identity-path", str(work / "identity"),
                       "--keypair-path", str(work / "agent.key"),
                       "--spool-directory", str(work / "spool"),
                       "--bootstrap-token-path", str(args.bootstrap_token),
                       "--fim-root", str(files)]
            # Persist reproducible configuration, without any credential values.
            save(work / "officer-remote-config.json", {"manager_url": args.manager_url,
                 "source": "all", "identity_path": str(work / "identity"),
                 "spool_directory": str(work / "spool"), "fim_root": str(files),
                 "response_enabled": True, "tls_verification": "Windows trust store"})
            agent = subprocess.Popen(command, cwd=work, stdout=stdout, stderr=stderr,
                                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                if agent.poll() is not None:
                    raise RuntimeError(f"agent exited before enrollment: {agent.returncode}")
                identity = work / "identity"
                if identity.exists() and len(identity.read_text().splitlines()) >= 3:
                    break
                time.sleep(1)
            else:
                raise TimeoutError("native verified-TLS enrollment did not complete")
            lines = identity.read_text().splitlines()
            result["agent_id"], result["host_id"] = lines[:2]
            auth = {"Authorization": "Bearer " + lines[2],
                    "X-Panopticon-Agent-Id": lines[0]}
            challenge = client.post("/api/v2/endpoint/freshness-challenge", headers=auth)
            result["freshness_challenge_status"] = challenge.status_code
            challenge.raise_for_status()
            # Give the production collectors time to subscribe after enrollment.
            time.sleep(15)
            target = subprocess.Popen(["ping.exe", "-n", "600", "127.0.0.1"],
                                      stdout=subprocess.DEVNULL,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
            marker = "panopticon-cross-vm-" + uuid4().hex[:12]
            probe_file = files / (marker + ".txt")
            probe_file.write_text(marker, encoding="ascii")
            result.update(target_pid=target.pid, marker=marker, probe_file=str(probe_file),
                          ready=True)
            save(status_path, result)
            deadline = time.monotonic() + 420
            while not stop.exists() and time.monotonic() < deadline:
                if agent.poll() is not None:
                    raise RuntimeError(f"agent exited during telemetry upload: {agent.returncode}")
                # Harmless file writes generate real file activity after FIM starts.
                with probe_file.open("a", encoding="ascii") as output:
                    output.write("\nowned probe")
                time.sleep(2)
            if not stop.exists():
                raise TimeoutError("host did not finish cross-VM verification")
            result["target_exited_before_cleanup"] = target.poll() is not None
            result["target_exit_code"] = target.poll()
            result["passed"] = result["target_exited_before_cleanup"]
    except (OSError, RuntimeError, ValueError, httpx.HTTPError,
            subprocess.SubprocessError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if agent is not None and agent.poll() is None:
            agent.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                agent.wait(timeout=60)
                result["agent_exit"] = agent.returncode
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait()
                result["agent_exit"] = "forced_after_timeout"
        if target is not None and target.poll() is None:
            target.kill()
            target.wait()
        stdout.close()
        stderr.close()
        result["passed"] = result["passed"] and result.get("agent_exit") == 0
        result["finished"] = True
        save(status_path, result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
