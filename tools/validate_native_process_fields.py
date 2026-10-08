"""Verify source-scoped native process scalars in exported guest originals.

Synthetic TDH payload fixtures are reported separately from live guest capture.
Neither establishes verified creator/parent aliases or complete source coverage.
"""
import argparse
import collections
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def native_fields(record):
    native = record["data"]["source_facts"]["process"].get("native_fields")
    if record["provenance"]["kind"] != "etw":
        require(native is None, "another source advertises native ETW scalars")
        return None
    require(native and native["format"] == "windows_etw_process_fields_v1", "native field body missing")
    require(native["event_id"] == (2 if record["category"] == "process_stop" else 1),
            "source operation mismatch")
    require(record["provenance"]["provider"] == "Microsoft-Windows-Kernel-Process" and
            native["provider_guid"] == "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", "source scope mismatch")
    require(all(native[name] is False for name in ("full_native_payload_retained",
            "parent_instance_verified", "sequence_alias_promotion_performed")), "unqualified native claim")
    require(len(native["fields"]) == 19, "selected scalar set incomplete")
    for field in native["fields"].values():
        require(field["value_interpreted"] is False, "raw enum/flag interpreted")
        require(field["state"] in ("healthy", "unsupported", "unavailable"), "invalid field state")
        if field["state"] == "healthy":
            value = field["value"]
            require(isinstance(value, str) and str(int(value)) == value and int(value) >= 0,
                    "noncanonical unsigned carrier")
            require(field["native_in_type"] in (8, 10), "copied non-unsigned type")
            bits = 32 if field["native_in_type"] == 8 else 64
            require(int(value) < 2**bits and field["reported_bytes"] == bits // 8 and
                    field["native_status"] == "0", "carrier/native read evidence mismatch")
        else:
            require(field["value"] is None, "refused scalar retains a value")
    return native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence-directory", "build", "schema", "manager-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord
    root = args.evidence_directory.resolve()
    schema = Draft202012Validator(json.loads(args.schema.read_text(encoding="utf-8")))
    fixture_file = root / "native-process-field-component-fixtures.json"
    require(not fixture_file.exists(), "preserve fixture originals")
    with fixture_file.open("xb") as output:
        subprocess.run([str(args.build.resolve() / "officer-process-lifecycle-tests.exe"),
                        "--emit-fixtures"], stdout=output, check=True, timeout=90)
    fixtures = json.loads(fixture_file.read_text(encoding="utf-8"))
    def verify_record(record):
        schema.validate(record)
        parsed = EndpointRecord.model_validate_json(json.dumps(record))
        require(parsed.model_dump(mode="json")["data"] == record["data"], "Manager altered native body")
        return native_fields(record)
    fixture_versions = []
    for record in fixtures:
        native = verify_record(record)
        if native:
            fixture_versions.append([native["event_id"], native["event_version"]])
    stats, versions, count = collections.Counter(), collections.Counter(), 0
    with (root / "recovered-records.ndjson").open(encoding="utf-8-sig") as source:
        for line in source:
            record = json.loads(line)
            if record["category"] not in ("process", "process_stop"):
                continue
            native = verify_record(record)
            if native:
                count += 1
                versions[f'{native["event_id"]}:{native["event_version"]}'] += 1
                for name, field in native["fields"].items():
                    stats[f'{name}:{field["state"]}'] += 1
    require(count, "no live native scalar bodies")
    runtime = json.loads((root / "runtime-report.json").read_text(encoding="utf-8-sig"))
    report = {
        "scope": "live_guest_etw_selected_scalar_retention_and_separate_synthetic_tdh_payload_fixtures",
        "live_native_records": count, "live_event_id_version_counts": dict(versions),
        "live_field_state_counts": dict(stats), "synthetic_fixture_versions": fixture_versions,
        "owned_lifecycle_sequence_consistent": runtime["NativeSequenceLifecycleConsistent"],
        "parent_instance_verified": False, "sequence_alias_promotion_verified": False,
        "full_native_payload_retained": False, "full_qualification": False,
    }
    target = root / "native-process-fields-report.json"
    require(not target.exists(), "preserve existing report")
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(target)}))


if __name__ == "__main__":
    main()
