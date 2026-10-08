"""Verify Device Guard evidence from an owned real-Windows runtime recovery run.

No host configuration writes. Records remain private in the supplied evidence
directory; stdout contains counts and qualification limits only.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def verify_body(body):
    require(body["format"] == "device_guard_state_v1", "unexpected format")
    for name in ("inventory_complete", "protection_verified", "policy_authority_verified",
                 "native_allocation_bounded", "collection_deadline_enforced"):
        require(body[name] is False, f"unsupported claim: {name}")
    require(int(body["collection_completed_uptime_ms"]) >=
            int(body["collection_started_uptime_ms"]), "capture clock reversed")
    counts = collections.Counter()
    for row in body["entries"]:
        require(len(row["fields"]) == 10, "selected property missing")
        for field in row["fields"].values():
            counts[field["state"]] += 1
            require(field["protection_verified"] is False, "getter claims protection")
            require(field["policy_authority_verified"] is False, "getter claims authority")
            require(int(field["query_completed_uptime_ms"]) >=
                    int(field["query_started_uptime_ms"]), "getter clock reversed")
            if isinstance(field["value"], list):
                require(len(field["value"]) <= 64, "array exceeds bound")
                require(field["enum_values_interpreted"] is False, "unknown enum interpreted")
                require(all(isinstance(value, str) and 0 <= int(value) <= 0xffffffff
                            for value in field["value"]), "array loses uint32 carrier")
    return dict(counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-report", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--manager-root", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord

    run = json.loads(args.runtime_report.read_text(encoding="utf-8"))
    original = Path(run["original_ndjson"])
    reopened = Path(run["second_ndjson"])
    def digest(path):
        with path.open("rb") as source:
            return hashlib.file_digest(source, "sha256").hexdigest()
    require(digest(original) == digest(reopened) == run["readback_sha256"],
            "immutable recovery readbacks differ")
    validator = Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    captures, health, count = {}, [], 0
    with original.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            validator.validate(record)
            parsed = EndpointRecord.model_validate_json(line)
            require(parsed.model_dump(mode="json")["data"] == record["data"],
                    "Manager altered native body")
            count += 1
            if record["category"] == "device_guard_state":
                require(record["record_id"] not in captures, "duplicate capture identity")
                captures[record["record_id"]] = record
            if record["kind"] == "health" and "device_guard_state" in record["data"]:
                health.append(record["data"]["device_guard_state"])
    require(captures, "no durable native Device Guard capture")
    qualities = [verify_body(record["data"]) for record in captures.values()]
    committed = [state for state in health if state.get("last_committed_record_id")]
    require(committed, "no health evidence for committed capture")
    for state in committed:
        record = captures[state["last_committed_record_id"]]
        require(state["last_committed_query_status"] == record["data"],
                "health does not bind exact source body")
        require(state["capture_freshness"]["record_id"] == record["record_id"],
                "freshness binds a different record")
        require(state["capture_freshness"]["state"] == "healthy", "capture already stale")
        require(int(state["last_committed_capture_started_uptime_ms"]) <=
                int(record["data"]["collection_started_uptime_ms"]) <=
                int(record["data"]["collection_completed_uptime_ms"]) <=
                int(state["last_committed_uptime_ms"]), "commit/capture order invalid")
    fixture_path = original.parent / "device-guard-native-component.json"
    require(not fixture_path.exists(), "preserve existing component evidence")
    with fixture_path.open("wb") as output:
        subprocess.run([str(args.build.resolve() / "officer-device-guard-tests.exe"),
                        "--emit-live"], stdout=output, check=True, timeout=150)
    native = json.loads(fixture_path.read_text(encoding="utf-8"))
    require(len(native) == 1, "native probe record count")
    validator.validate(native[0])
    EndpointRecord.model_validate_json(json.dumps(native[0]))
    native_quality = verify_body(native[0]["data"])
    report = {
        "scope": "real_windows_host_device_guard_provider_owned_runtime_abrupt_exit_reopen",
        "schema_and_manager_body_preservation_records": count,
        "durable_device_guard_captures": len(captures),
        "committed_health_bindings": len(committed),
        "runtime_property_quality_counts": qualities,
        "native_component_property_quality_counts": native_quality,
        "readback_sha256": run["readback_sha256"],
        "effective_enforcement_verified": False,
        "vm_qualification_verified": False,
        "cross_version_qualification_verified": False,
        "full_qualification": False,
    }
    report_path = original.parent / "device-guard-report.json"
    require(not report_path.exists(), "preserve existing verification report")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(report_path)}))


if __name__ == "__main__":
    main()
