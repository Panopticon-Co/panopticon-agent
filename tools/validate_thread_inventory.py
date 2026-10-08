"""Verify original guest thread captures, durable replay and common contracts.

This proves sampled native observations, not thread lifecycle/injection coverage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--manager-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_directory.resolve()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord
    validator = Draft202012Validator(load(args.schema))
    for entry in load(root / "SHA256.json"):
        name = entry["File"]
        require(Path(name).name == name and "/" not in name and "\\" not in name, "unsafe manifest name")
        require(digest(root / name).lower() == entry["Hash"].lower(), "package bytes changed")
    components = load(root / "component-results.json")
    expected = 24 if (root / "officer-memory-inventory-tests.exe").is_file() else 23 if (root / "officer-usn-journal-tests.exe").is_file() else 22
    require(len(components) == expected and len({r["Test"] for r in components}) == expected,
            "consolidated component execution list required")
    require(any(r["Test"] == "officer-thread-inventory-tests" for r in components), "thread component absent")
    require(all(type(r["ExitCode"]) is int and r["ExitCode"] == 0 and r["TimedOut"] is False for r in components), "component failure")
    original = root / "recovered-records.ndjson"
    require(digest(original) == digest(root / "reopened-records.ndjson"), "reopen changed original records")
    selected = {}; health = []; count = 0
    with original.open(encoding="utf-8-sig") as file:
        for line in file:
            record = json.loads(line); validator.validate(record)
            require(EndpointRecord.model_validate_json(line).model_dump(mode="json")["data"] == record["data"], "Manager altered body")
            count += 1
            if record["category"].startswith("thread_inventory"):
                require(record["record_id"] not in selected, "duplicate original thread record")
                selected[record["record_id"]] = record
            if record["kind"] == "health":
                health.append(record)
    manifests = [r for r in selected.values() if r["category"] == "thread_inventory"]
    require(len(manifests) == 1, "one final thread capture required")
    manifest = manifests[0]; data = manifest["data"]
    require(data["inventory_complete"] is False and data["owner_process_instances_verified"] is False
            and data["thread_lifecycle_complete"] is False, "unqualified thread claim")
    capture = data["capture_id"]
    require(capture in selected and selected[capture]["category"] == "thread_inventory_begin", "durable begin absent")
    ids = data["page_record_ids"]
    require(len(ids) == len(set(ids)) == int(data["pages_produced"]), "ambiguous page manifest")
    rows = exact = refusals = 0
    for index, page_id in enumerate(ids):
        require(page_id in selected, "manifest page absent")
        page = selected[page_id]
        require(page["category"] == "thread_inventory_page" and page["data"]["capture_id"] == capture
                and page["data"]["page_index"] == str(index), "page scope/order mismatch")
        for row in page["data"]["entries"]:
            rows += 1
            if row.get("entry_kind") == "row_copy_refusal":
                refusals += 1; continue
            query = row["later_tid_query"]
            if "reference" not in query:
                require(query["value"] is None and query["error_domain"] == "Win32" and query["error_code"].isdecimal(), "refused query invented value")
                refusals += 1; continue
            require(query["owner_process_reference"] is None and query["owner_process_instance_verified"] is False
                    and query["start_address"] is None and query["start_address_queried"] is False, "unsafe owner/start address inference")
            ref = query["reference"]
            require(ref["boot_id"] == page["endpoint"]["boot_id"] and ref["observed_tid"] == row["snapshot_descriptor"]["tid"], "identity scope mismatch")
            if ref["resolution"] == "native_exact":
                require(ref["boot_id"] and int(ref["native_creation_ticks"]) > 0, "incomplete exact identity")
                values = [page["endpoint"]["host_id"], ref["boot_id"], str(ref["observed_tid"]), ref["native_creation_ticks"]]
                opaque = "windows-thread-instance-v1" + "".join(str(len(v.encode("utf-8"))) + ":" + v for v in values)
                require(ref["entity_id"] == "thread_" + hashlib.sha256(opaque.encode()).hexdigest(), "thread entity changed native tuple")
                exact += 1
            else:
                require(ref["resolution"] == "unresolved" and ref["entity_id"] is None, "invented unresolved identity")
            if query["times"]["state"] == "healthy":
                require(query["times"]["value"]["exit_ticks"] is None, "undefined exit time interpreted")
    require(rows == int(data["entries_delivered"]) and exact > 0, "missing native thread accounting")
    bindings = 0
    for record in health:
        status = record["data"].get("thread_inventory", {})
        if status.get("last_committed_record_id") != manifest["record_id"]:
            continue
        require(status["last_committed_query_status"]["entries_delivered"] == str(rows), "health manifest accounting mismatch")
        require(status["capture_freshness"]["record_id"] == manifest["record_id"], "freshness record binding mismatch")
        bindings += 1
    require(bindings > 0, "no committed thread health binding")
    report = {"scope": "native guest sampled thread capture and abrupt-exit original recovery", "schema_and_manager_records": count,
              "component_runs": len(components), "thread_pages": len(ids), "thread_rows": rows, "native_exact_references": exact,
              "row_or_open_refusals": refusals, "query_failures": data["query_failure_count"], "health_bindings": bindings,
              "enumeration_complete": data["enumeration_complete"], "originals_sha256": digest(original),
              "owner_process_instances_verified": False, "continuous_thread_coverage_verified": False, "full_qualification": False}
    target = root / "thread-inventory-report.json"; require(not target.exists(), "preserve existing report")
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({**report, "report_path": str(target)}))


if __name__ == "__main__":
    main()
