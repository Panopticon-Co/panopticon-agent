"""Validate process graph fixtures and owned native Windows recovery evidence.

Positive fixture ancestry is never counted as live ETW or VM qualification.
Existing evidence is preserved. Run against a stopped owned runtime journal.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("runtime-report", "build", "schema", "manager-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord

    run = json.loads(args.runtime_report.read_text(encoding="utf-8"))
    original, reopened = Path(run["original_ndjson"]), Path(run["second_ndjson"])
    def digest(path):
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()
    require(digest(original) == digest(reopened) == run["readback_sha256"],
            "recovery originals differ")
    validator = Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    def validate(record):
        validator.validate(record)
        parsed = EndpointRecord.model_validate_json(json.dumps(record))
        require(parsed.model_dump(mode="json")["data"] == record["data"],
                "Manager altered native body")
    build = args.build.resolve()
    fixture_path = original.parent / "process-graph-component-fixtures.json"
    if not fixture_path.exists():
        with fixture_path.open("xb") as output:
            subprocess.run([str(build / "officer-process-graph-tests.exe"), "--emit-fixtures"],
                           stdout=output, check=True, timeout=90)
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
    for record in fixtures:
        validate(record)
    health, count = [], 0
    with original.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            validate(record)
            count += 1
            journal = record["data"].get("journal", {}) if record["kind"] == "health" else {}
            if "process_graph" in journal:
                graph = journal["process_graph"]
                archived = int(journal["process_history"]["records"])
                indexed = int(graph["indexed_records"])
                unresolved = int(graph["unresolved_or_refused_records"])
                require(0 <= unresolved <= indexed <= archived, "graph counters inconsistent")
                require(int(graph["archive_backlog"]) == archived - indexed, "backlog differs")
                require(graph["state"] == "degraded", "runtime graph claims full coverage")
                health.append(journal)
    require(health, "no durable graph health evidence")
    spool = Path(run["evidence_directory"]) / "spool"
    archive_path = original.parent / "process-history-originals.ndjson"
    if not archive_path.exists():
        with archive_path.open("xb") as output:
            subprocess.run([str(build / "officer-host-inventory-tests.exe"),
                            "--read-process-history-lines", str(spool)],
                           stdout=output, check=True, timeout=90)
    archive = [json.loads(line) for line in archive_path.read_text(encoding="utf-8").splitlines()]
    for record in archive:
        validate(record)
    # Health is a pre-commit sample, not an atomic terminal archive manifest.
    require(int(health[-1]["process_history"]["records"]) <= len(archive),
            "terminal archive lost sampled lifecycle evidence")
    roots = {record.get("subject", {}).get("entity_id") for record in archive}
    roots.discard(None)
    fixture_root = fixtures[0]["subject"]["entity_id"]
    roots.add(fixture_root)  # An absent identity must not fabricate ancestry.
    queries = []
    for root in sorted(roots):
        probe = subprocess.run([str(build / "officer-process-graph-tests.exe"),
                                "--read-ancestry", str(spool), root],
                               capture_output=True, check=True, timeout=90)
        graph = json.loads(probe.stdout)
        require(graph["source_coverage_complete"] is False and
                graph["creator_relationship_verified"] is False, "unqualified graph claim")
        require(all(node["liveness"] is None for node in graph["nodes"]), "inferred liveness")
        if root == fixture_root:
            require(len(graph["nodes"]) == 1 and not graph["nodes"][0]["evidence"] and
                    not graph["edges"], "fixture identity leaked into runtime journal")
        queries.append(graph)
    query_path = original.parent / "process-ancestry-queries.json"
    require(not query_path.exists(), "preserve existing query evidence")
    query_path.write_text(json.dumps(queries, indent=2), encoding="utf-8")
    report = {
        "scope": "real_windows_host_owned_runtime_abrupt_exit_reopen_and_separate_graph_fixtures",
        "schema_and_manager_body_preservation_records": count,
        "component_fixture_records": len(fixtures),
        "durable_graph_health_records": len(health),
        "archived_runtime_lifecycle_records": len(archive),
        "runtime_ancestry_queries": len(queries),
        "positive_live_ancestry_verified": False,
        "creator_relationship_verified": False,
        "vm_qualification_verified": False,
        "full_qualification": False,
        "readback_sha256": run["readback_sha256"],
    }
    report_path = original.parent / "process-graph-report.json"
    require(not report_path.exists(), "preserve existing report")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(report_path)}))


if __name__ == "__main__":
    main()
