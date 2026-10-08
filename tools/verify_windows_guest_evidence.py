"""Verify exported dedicated-guest evidence without opening guest DPAPI state.

Native captures are validated against the common envelope and Manager body
preservation only; this does not exercise the Detection Engine or qualify a fleet.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--manager-root", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord
    root = args.evidence_directory.resolve()
    runtime = load(root / "runtime-report.json")
    require(runtime["FullQualification"] is False, "unqualified runtime claim")
    for entry in load(root / "SHA256.json"):
        name = entry["File"]
        require(Path(name).name == name and "/" not in name and "\\" not in name,
                "manifest escapes evidence directory")
        require(digest(root / name).lower() == entry["Hash"].lower(), "package hash mismatch")
    components = load(root / "component-results.json")
    expected_components = 24 if (root / "officer-memory-inventory-tests.exe").is_file() else 23 if (root / "officer-usn-journal-tests.exe").is_file() else 22 if (root / "officer-thread-inventory-tests.exe").is_file() else 21
    require(len(components) == expected_components and len({row["Test"] for row in components}) == expected_components,
            "component execution list incomplete")
    if expected_components >= 22:
        require(any(row["Test"] == "officer-thread-inventory-tests" for row in components),
                "native thread component evidence missing")
    if expected_components == 24:
        require(any(row["Test"] == "officer-memory-inventory-tests" for row in components)
                and load(root / "memory-component-report.json")["real_windows_memory_region_verified"] is True,
                "required native memory component evidence missing")
    if expected_components >= 23:
        require(any(row["Test"] == "officer-usn-journal-tests" for row in components)
                and load(root / "usn-component-report.json")["real_windows_usn_verified"] is True,
                "required native USN component evidence missing")
    require(all(type(row["ExitCode"]) is int and row["ExitCode"] == 0 and
                row["TimedOut"] is False for row in components), "native component failure")
    validator = Draft202012Validator(load(args.schema))
    originals, reopened = root / "recovered-records.ndjson", root / "reopened-records.ndjson"
    require(digest(originals) == digest(reopened), "guest recovery originals changed")
    record_count, logs, native_stops = 0, 0, {}
    with originals.open(encoding="utf-8-sig") as stream:
        for line in stream:
            record = json.loads(line)
            validator.validate(record)
            parsed = EndpointRecord.model_validate_json(line)
            require(parsed.model_dump(mode="json")["data"] == record["data"],
                    "Manager altered native body")
            record_count += 1
            logs += record["category"] == "windows_event_log"
            if record["category"] == "process_stop" and record["provenance"]["kind"] == "etw":
                native_stops[record["record_id"]] = record
    require(record_count == runtime["RecordCount"] and logs == runtime["NativeLogRecords"],
            "runtime counts differ from originals")
    history = root / "process-history.ndjson"
    require(digest(history) == digest(root / "process-history-reopened.ndjson"),
            "guest lifecycle originals changed")
    archive, archived_stops = [], set()
    with history.open(encoding="utf-8-sig") as stream:
        for line in stream:
            record = json.loads(line)
            validator.validate(record)
            archive.append(record)
            if record["record_id"] in native_stops:
                require(record == native_stops[record["record_id"]], "archive altered stop body")
                archived_stops.add(record["record_id"])
    require(len(archive) == runtime["ProcessHistoryRecords"], "archive count differs")
    require(runtime["ProcessStopVerified"] is True and
            runtime["RetainedExactLifecycleGraphVerified"] is True, "owned native lifecycle unverified")
    lifecycle = load(root / "lifecycle-report.json")
    expected = lifecycle["Expected"]
    require(lifecycle["Verified"] is True and expected["Completed"] is True,
            "owned process did not complete")
    stops = lifecycle["MatchingNativeStops"]
    require(len(stops) == 1, "ambiguous owned process stop")
    stop = stops[0]
    require(stop["record_id"] in archived_stops and stop == native_stops[stop["record_id"]],
            "owned stop missing from exact delivery/archive evidence")
    require(stop["data"]["process"]["pid"] == expected["Pid"] and
            stop["data"]["process"]["start_time_ticks"] == expected["CreationTicks"] and
            stop["data"]["lifecycle"]["exit_code"] == str(expected["ExitCode"]),
            "owned target identity/exit mismatch")
    graph = load(root / "process-ancestry.json")
    require(graph["source_coverage_complete"] is False and
            graph["creator_relationship_verified"] is False and
            graph["alias_promotion_performed"] is False, "graph overclaims authority")
    entity = stop["subject"]["entity_id"]
    nodes = [node for node in graph["nodes"] if node["entity_id"] == entity]
    require(len(nodes) == 1 and nodes[0]["stop_observed"] is True and
            nodes[0]["liveness"] is None and
            any(row["record_id"] == stop["record_id"] for row in nodes[0]["evidence"]),
            "graph does not bind exact stop")
    report = {
        "scope": "dedicated_windows_guest_exported_native_component_and_owned_runtime_evidence",
        "os": runtime["OS"], "build": runtime["Build"],
        "native_component_executions": len(components),
        "schema_and_manager_body_preservation_records": record_count,
        "native_log_records": logs,
        "archived_lifecycle_records": len(archive),
        "owned_native_stop_verified": True,
        "retained_exact_lifecycle_graph_verified": True,
        "positive_parent_ancestry_verified": False,
        "full_source_coverage_verified": False,
        "full_qualification": False,
        "originals_sha256": digest(originals), "history_sha256": digest(history),
    }
    output = root / "host-verification-report.json"
    require(not output.exists(), "preserve existing verification report")
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(output)}))


if __name__ == "__main__":
    main()
