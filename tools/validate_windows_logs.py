"""Owned, bounded Windows host/VM runtime validation; never drives Detection.

Run with a Python environment containing jsonschema. Evidence stays in a new
directory; abrupt termination targets only the process created here.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import subprocess
import time
import uuid

import jsonschema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True, type=pathlib.Path)
    parser.add_argument("--schema", required=True, type=pathlib.Path)
    parser.add_argument("--evidence-root", required=True, type=pathlib.Path)
    args = parser.parse_args()
    build = args.build.resolve()
    evidence = args.evidence_root.resolve() / ("winevt-runtime-" + uuid.uuid4().hex)
    evidence.mkdir(parents=True, exist_ok=False)
    spool = evidence / "spool"
    schema = jsonschema.Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    fixture = json.loads(subprocess.check_output([str(build / "officer-windows-event-log-tests.exe"), "--emit-fixtures"], encoding="utf-8"))
    for record in fixture:
        schema.validate(record)
    # Diagnostic files are independent of durable capture and avoid pipe stalls.
    with (evidence / "stdout.ndjson").open("wb") as out, (evidence / "stderr.txt").open("wb") as err:
        agent = subprocess.Popen([str(build / "officer-agent.exe"), "--source", "sysmon", "--spool-directory", str(spool)], stdout=out, stderr=err)
        try:
            time.sleep(12)
            if agent.poll() is not None:
                raise RuntimeError(f"owned agent exited before validation: {agent.returncode}")
        finally:
            if agent.poll() is None:
                agent.kill()
            agent.wait(timeout=20)
    records = json.loads(subprocess.check_output([str(build / "officer-host-inventory-tests.exe"), "--read-spool", str(spool)], encoding="utf-8"))
    for record in records:
        schema.validate(record)
    logs = [record for record in records if record["category"] == "windows_event_log"]
    health = [record for record in records if record["kind"] == "health" and "windows_event_log" in record["data"]]
    if not logs or not health:
        raise RuntimeError("no native log observations or per-channel runtime health recovered")
    ids = [record["record_id"] for record in records]
    if len(ids) != len(set(ids)):
        raise RuntimeError("canonical record identity collision")
    for record in logs:
        assert record["subject"] is None and record["data"]["actor_verified"] is False
        assert record["provenance"]["kind"] == "windows_event_log"
        assert record["data"]["rendered_xml"]
    channels = health[-1]["data"]["windows_event_log"]["channels"]
    if len(channels) != 8:
        raise RuntimeError("health omitted configured Windows channels")
    # Reopening the same spool must preserve originals, independent of display.
    reopened = json.loads(subprocess.check_output([str(build / "officer-host-inventory-tests.exe"), "--read-spool", str(spool)], encoding="utf-8"))
    assert reopened == records
    report = {"scope": "real_windows_owned_agent_abrupt_exit_and_journal_reopen", "record_count": len(records),
        "native_log_record_count": len(logs), "native_log_channels": dict(collections.Counter(record["provenance"]["channel"] for record in logs)),
        "channel_health": channels, "health_count": len(health), "fixture_schema_records": len(fixture),
        "windows_vm_qualification": "not_implied_by_host_run", "evidence_directory": str(evidence)}
    (evidence / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
