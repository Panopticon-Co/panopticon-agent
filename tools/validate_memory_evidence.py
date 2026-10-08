"""Verify selected real-Windows VirtualQueryEx component evidence.

This validates bounded held-process region metadata only. It does not qualify
content inspection, injection detection, all-process coverage or a verdict.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def contains(entry, address):
    return int(entry["base_address"]) <= address < int(entry["base_address"]) + int(entry["region_bytes"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--manager-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_directory.resolve()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord
    for entry in load(root / "SHA256.json"):
        name = entry["File"]
        require(Path(name).name == name and "/" not in name and "\\" not in name, "unsafe manifest name")
        require(digest(root / name).lower() == entry["Hash"].lower(), "export bytes changed")
    components = load(root / "component-results.json")
    require(len(components) == len({item["Test"] for item in components}) == 24
            and all(item["ExitCode"] == 0 and item["TimedOut"] is False for item in components)
            and any(item["Test"] == "officer-memory-inventory-tests" for item in components), "memory component did not complete")
    component = load(root / "memory-component-report.json")
    for name in ("real_windows_memory_region_verified", "held_process_identity_verified", "rw_and_rx_regions_verified", "open_refusal_verified"):
        require(component[name] is True, "missing component claim: " + name)
    require(component["content_read"] is False and component["injection_verified"] is False
            and component["full_memory_coverage_verified"] is False, "memory component overclaims scope")
    validator = Draft202012Validator(load(args.schema))
    records = component["records"]
    pages, manifest = [], None
    for record in records:
        validator.validate(record)
        require(EndpointRecord.model_validate(record).model_dump(mode="json")["data"] == record["data"], "Manager altered memory body")
        if record["category"] == "memory_region_inventory_page":
            pages.append(record)
        elif record["category"] == "memory_region_inventory":
            require(manifest is None, "duplicate memory manifest")
            manifest = record
    require(manifest is not None and pages and manifest["data"]["memory_inventory_complete"] is False
            and manifest["data"]["content_read"] is False and manifest["data"]["injection_verified"] is False,
            "memory manifest absent or overclaims")
    page_ids = {record["record_id"] for record in pages}
    require(set(manifest["data"]["page_record_ids"]).issubset(page_ids), "manifest references absent pages")
    owned = component["owned"]
    pid, rw, rx = int(owned["pid"]), int(owned["rw_address"]), int(owned["rx_address"])
    rw_row = rx_row = None
    refusal = False
    for page in pages:
        for row in page["data"]["entries"]:
            kind = row["entry_kind"]
            if kind == "process_open_refusal" and row["requested_pid"] == 0:
                refusal = row["process_reference"] is None and row["query"]["state"] == "unavailable"
            if kind != "memory_region" or row["process_reference"]["observed_pid"] != pid:
                continue
            require(row["content_read"] is False and row["injection_verified"] is False and row["mapping_instance_identity"] is None,
                    "region metadata made unsupported claim")
            if contains(row, rw):
                rw_row = row
            if contains(row, rx):
                rx_row = row
    require(refusal and rw_row is not None and rx_row is not None, "owned process/refusal evidence missing")
    require(rw_row["native_state"] == "4096" and rw_row["native_type"] == "131072"
            and rw_row["write_capable_reported"] is True and rw_row["executable_reported"] is False
            and rw_row["private_executable_reported"] is False, "owned RW region incorrect")
    require(rx_row["native_state"] == "4096" and rx_row["native_type"] == "131072"
            and rx_row["write_capable_reported"] is False and rx_row["executable_reported"] is True
            and rx_row["private_executable_reported"] is True, "owned RX region incorrect")
    report = {"scope": "real held-process VirtualQueryEx metadata component", "component_records_checked": len(records),
              "page_records_checked": len(pages), "owned_rw_rx_regions_verified": True, "open_refusal_verified": True,
              "schema_and_manager_body_verified": True, "component_report_sha256": digest(root / "memory-component-report.json"),
              "content_read": False, "injection_verified": False, "full_qualification": False}
    target = root / "memory-verification-report.json"
    require(not target.exists(), "preserve existing verification report")
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(target)}))


if __name__ == "__main__":
    main()
