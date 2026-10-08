"""Owned real-Windows capture, original WAL readback and persistence assembly.

Evidence contains native configuration. Keep it private; printed reports contain
counts/status only. No task, subscription or startup configuration is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import time
import uuid

import jsonschema

PERSISTENCE_SOURCES = (
    "scheduled_task_inventory",
    "wmi_subscription_inventory",
    "startup_inventory",
)
IDENTITY_SOURCES = (
    "account_inventory",
    "local_group_inventory",
    "logon_session_inventory",
    "terminal_session_inventory",
)
SOFTWARE_SOURCES = ("msi_product_inventory", "uninstall_registry_inventory")


def verify_capture(records: list[dict], manifest: dict) -> dict:
    originals = {record["record_id"]: record for record in records}
    data = manifest["data"]
    source = manifest["category"]
    begin = originals[data["capture_id"]]
    assert begin["category"] == source + "_begin"
    assert begin["kind"] == "state" and begin["subject"] is None
    rows = 0
    for index, record_id in enumerate(data["page_record_ids"]):
        page = originals[record_id]
        assert page["category"] == source + "_page" and page["subject"] is None
        assert page["data"]["page_index"] == str(index)
        assert page["data"]["capture_id"] == begin["record_id"]
        assert page["data"]["inventory_complete"] is False
        assert page["endpoint"] == manifest["endpoint"]
        assert (
            page["provenance"]["collector_generation"]
            == manifest["provenance"]["collector_generation"]
        )
        rows += len(page["data"]["entries"])
    assert data["entries_delivered"] == str(rows)
    assert data["pages_produced"] == str(len(data["page_record_ids"]))
    assert manifest["subject"] is None and data["inventory_complete"] is False
    return {
        "source": source,
        "state": data["state"],
        "entries": rows,
        "pages": len(data["page_record_ids"]),
        "enumeration_complete": data["enumeration_complete"],
        "query_failure_count": data["query_failure_count"],
        "copy_refusal_count": data["copy_refusal_count"],
        "soft_budget_exceeded": data["soft_budget_exceeded"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--schema", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--source", choices=("sysmon", "etw", "all"), default="sysmon")
    parser.add_argument("--recheck-evidence", type=pathlib.Path)
    parser.add_argument(
        "--surface",
        choices=("persistence", "identity", "both", "software"),
        default="persistence",
    )
    args = parser.parse_args()
    sources = PERSISTENCE_SOURCES if args.surface == "persistence" else IDENTITY_SOURCES
    if args.surface == "both":
        sources = PERSISTENCE_SOURCES + IDENTITY_SOURCES
    elif args.surface == "software":
        sources = SOFTWARE_SOURCES
    if not 10 <= args.seconds <= 120:
        parser.error("capture duration must be 10..120 seconds")
    build = args.build.resolve()
    evidence = (
        args.recheck_evidence.resolve()
        if args.recheck_evidence
        else (args.evidence_root.resolve() / ("persistence-runtime-" + uuid.uuid4().hex))
    )
    if args.recheck_evidence:
        if not (evidence / "spool" / "journal.db").is_file():
            raise RuntimeError("recheck requires an existing stopped evidence spool")
    else:
        evidence.mkdir(parents=True, exist_ok=False)
    validator = jsonschema.Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    fixture = []
    if args.recheck_evidence:
        fixture = json.loads(
            (evidence / "native-component-records.json").read_text(encoding="utf-8")
        )
    else:
        binaries = ["officer-identity-inventory-tests.exe"]
        if args.surface == "persistence":
            binaries = ["officer-persistence-inventory-tests.exe"]
        elif args.surface == "both":
            binaries.append("officer-persistence-inventory-tests.exe")
        elif args.surface == "software":
            binaries = ["officer-software-inventory-tests.exe"]
        for binary in binaries:
            fixture.extend(
                json.loads(
                    subprocess.check_output(
                        [str(build / binary), "--emit-live"],
                        encoding="utf-8",
                        timeout=90,
                    )
                )
            )
    for record in fixture:
        validator.validate(record)
    fixture_results = [
        verify_capture(fixture, record) for record in fixture if record["category"] in sources
    ]
    if not args.recheck_evidence:
        (evidence / "native-component-records.json").write_text(
            json.dumps(fixture), encoding="utf-8"
        )
    spool = evidence / "spool"
    if not args.recheck_evidence:
        with (
            (evidence / "stdout.ndjson").open("wb") as out,
            (evidence / "stderr.txt").open("wb") as err,
        ):
            agent = subprocess.Popen(
                [
                    str(build / "officer-agent.exe"),
                    "--source",
                    args.source,
                    "--spool-directory",
                    str(spool),
                ],
                stdout=out,
                stderr=err,
            )
            try:
                time.sleep(args.seconds)
                if agent.poll() is not None:
                    raise RuntimeError(f"owned endpoint exited prematurely: {agent.returncode}")
            finally:
                if agent.poll() is None:
                    agent.kill()
                agent.wait(timeout=20)
    probe = [
        str(build / "officer-host-inventory-tests.exe"),
        "--read-spool-lines",
        str(spool),
    ]
    recovered_file = evidence / ("recovered-" + uuid.uuid4().hex + ".ndjson")
    with recovered_file.open("wb") as output:
        subprocess.run(probe, stdout=output, check=True, timeout=120)
    ids = set()
    records = []
    record_count = 0
    with recovered_file.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            validator.validate(record)
            assert record["record_id"] not in ids, "record identity collision"
            ids.add(record["record_id"])
            record_count += 1
            if record["kind"] == "health" or record["category"].startswith(sources):
                records.append(record)
    manifests = [record for record in records if record["category"] in sources]
    assert {record["category"] for record in manifests} == set(sources), (
        "native state manifests missing after bounded run; evidence is partial"
    )
    runtime_results = [verify_capture(records, record) for record in manifests]
    originals = {record["record_id"]: record for record in records}
    health = [record for record in records if record["kind"] == "health"]
    statuses = {}
    for source in sources:
        accepted = [
            record["data"][source]
            for record in health
            if record["data"].get(source, {}).get("last_committed_record_id")
        ]
        assert accepted, f"no committed capture health for {source}"
        status = accepted[-1]
        manifest = originals[status["last_committed_record_id"]]
        assert manifest["category"] == source
        assert (
            status["last_committed_query_status"]["query_failure_count"]
            == manifest["data"]["query_failure_count"]
        )
        assert status["capture_freshness"]["record_id"] == manifest["record_id"]
        assert status["capture_freshness"]["state"] == "healthy"
        statuses[source] = {
            "state": status["state"],
            "freshness": status["capture_freshness"]["state"],
        }
    second_file = evidence / ("reopened-" + uuid.uuid4().hex + ".ndjson")
    with second_file.open("wb") as output:
        subprocess.run(probe, stdout=output, check=True, timeout=120)
    with recovered_file.open("rb") as first, second_file.open("rb") as second:
        digest = hashlib.file_digest(first, "sha256").hexdigest()
        assert digest == hashlib.file_digest(second, "sha256").hexdigest()
    report = {
        "scope": "real_windows_host_owned_endpoint_abrupt_exit_wal_reopen",
        "records": record_count,
        "fixture_schema_records": len(fixture),
        "component_captures": fixture_results,
        "runtime_captures": runtime_results,
        "committed_health": statuses,
        "full_qualification": False,
        "surface": args.surface,
        "vm_qualification": "not_implied",
        "evidence_directory": str(evidence),
        "original_ndjson": str(recovered_file),
        "second_ndjson": str(second_file),
        "readback_sha256": digest,
    }
    selected_path = evidence / ("verified-captures-" + uuid.uuid4().hex + ".json")
    selected_path.write_text(json.dumps(records), encoding="utf-8")
    report_path = evidence / "report.json"
    if report_path.exists():
        report_path = evidence / ("report-recheck-" + uuid.uuid4().hex + ".json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
