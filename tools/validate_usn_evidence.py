"""Validate native guest USN fixtures, original runtime buffers and recovery.

Does not qualify all-volume/file baseline, actors, paths, V4 or kernel coverage.
"""
import argparse
import json
from pathlib import Path
import struct
import sys
from jsonschema import Draft202012Validator
from verify_windows_guest_evidence import digest, load, require


def check_batch(record):
    data = record["data"]
    require(record["subject"] is None and data["event_boot_id"] is None, "invented actor/event boot")
    require(data["full_native_buffer_retained"] is True and data["process_attribution_verified"] is False,
            "unsupported native-buffer/actor claim")
    native = bytes.fromhex(data["raw_native_buffer_hex"])
    require(len(native) == data["native_buffer_bytes"] and 8 <= len(native) <= 16384, "native buffer bound changed")
    next_usn, = struct.unpack_from("<q", native)
    require(str(next_usn) == data["next_usn"] and next_usn >= int(data["requested_start_usn"]), "native cursor changed")
    if data.get("state") == "blind" and not data["entries"]:
        return 0
    offset = 8
    for row in data["entries"]:
        length, major, minor = struct.unpack_from("<IHH", native, offset)
        require(length == row["record_length"] and major == row["major_version"] and minor == row["minor_version"], "native record header changed")
        require(length >= 8 and length % 8 == 0 and offset + length <= len(native), "native record span invalid")
        if major in (2, 3):
            extra = 16 if major == 3 else 0
            width = 16 if major == 3 else 8
            usn, timestamp, reason, source, security, attributes, name_length, name_offset = struct.unpack_from("<qqIIIIHH", native, offset + 24 + extra)
            require(row["usn"] == str(usn) and row["native_timestamp_filetime_signed"] == str(timestamp)
                    and row["reason_mask"] == str(reason) and row["source_info_mask"] == str(source)
                    and row["security_id"] == str(security) and row["file_attributes"] == str(attributes), "native scalars changed")
            require(row["file_id_native_bytes_hex"] == native[offset + 8:offset + 8 + width].hex()
                    and row["parent_file_id_native_bytes_hex"] == native[offset + 8 + width:offset + 8 + width * 2].hex(), "native file identifiers changed")
            name = native[offset + name_offset:offset + name_offset + name_length]
            require(row["filename_utf16le_hex"] == name.hex(), "native filename bytes changed")
            try:
                expected = name.decode("utf-16le", errors="strict")
            except UnicodeError:
                expected = None
            require(row["filename"] == expected and row["path"] is None and row["process_reference"] is None
                    and row["rename_pair_verified"] is False, "filename or uncertainty semantics changed")
        else:
            require(row["state"] == "unsupported" and row["raw_record_hex"] == native[offset:offset + length].hex(), "unknown version not preserved")
        offset += length
    require(offset == len(native), "native batch tail omitted")
    return len(data["entries"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--manager-root", type=Path, required=True)
    parser.add_argument("--component-only", action="store_true",
                        help="Require real native reopen/cursor-fault evidence; do not claim endpoint runtime qualification")
    args = parser.parse_args(); root = args.evidence_directory.resolve()
    sys.path.insert(0, str(args.manager_root.resolve()))
    from manager.wire.endpoint import EndpointRecord
    validator = Draft202012Validator(load(args.schema))
    for entry in load(root / "SHA256.json"):
        name = entry["File"]
        require(Path(name).name == name and "/" not in name and "\\" not in name, "unsafe manifest name")
        require(digest(root / name).lower() == entry["Hash"].lower(), "package hash changed")
    components = [] if args.component_only else load(root / "component-results.json")
    if args.component_only:
        require((root / "exit-code.txt").read_text().strip() == "0", "native component did not exit successfully")
    else:
        expected_components = 24 if (root / "officer-memory-inventory-tests.exe").is_file() else 23
        require(len(components) == len({r["Test"] for r in components}) == expected_components
                and all(type(r["ExitCode"]) is int and r["ExitCode"] == 0 and r["TimedOut"] is False for r in components), "native component failure")
    component = load(root / ("component-report.json" if args.component_only else "usn-component-report.json"))
    for key in ("real_windows_usn_verified", "create_ads_rename_delete_verified", "refusal_cursor_immutable_verified", "stopped_source_replay_verified", "held_file_index_verified"):
        require(component[key] is True, "required native USN component evidence absent: " + key)
    component_rows = 0
    for record in component["records"] + component["synthetic_contract_fixtures"]:
        validator.validate(record)
        require(EndpointRecord.model_validate(record).model_dump(mode="json")["data"] == record["data"], "Manager altered native component body")
        if record["category"] == "filesystem_usn_batch":
            component_rows += check_batch(record)
    fault_cases = []
    for fault in component.get("checkpoint_faults", []):
        require(fault["verified"] is True and fault["native_journal_modified"] is False, "fault evidence missing or modified native journal")
        case = fault["case"]; fault_cases.append(case)
        require(all(r in component["records"] for r in fault["records"]), "fault original absent from component originals")
        if case == "malformed-cursor":
            require(fault["malformed"] is True and not fault["records"] and fault["source_health"]["state"] == "blind"
                    and fault["source_health"]["checkpoint_revision"] == "0", "malformed checkpoint did not fail closed before native query")
            continue
        require(fault["malformed"] is False and fault["records"], "discontinuity evidence absent")
        gap = fault["records"][0]; body = gap["data"]
        bounds = body["native_journal"]; prior = body["previous_cursor"]; replacement = body["replacement_cursor"]
        first = max(int(bounds["first_usn"]), int(bounds["lowest_valid_usn"]))
        require(gap["category"] == "filesystem_usn_gap" and body["lost_native_events"] is None
                and body["source_checkpoint_expected_revision"] == "1"
                and replacement["journal_id"] == bounds["journal_id"] and replacement["next_usn"] == str(first)
                and body["source_checkpoint_next_cursor"] == replacement, "native gap/cursor transaction semantics changed")
        if case == "mismatched-journal":
            require(prior["journal_id"] != bounds["journal_id"] and body["reason"] == "native_journal_instance_changed", "wrong journal mismatch classification")
        elif case == "ahead-cursor":
            require(prior["journal_id"] == bounds["journal_id"] and int(prior["next_usn"]) > int(bounds["next_usn"])
                    and body["reason"] == "saved_cursor_ahead_of_native_journal", "wrong ahead cursor classification")
        elif case == "expired-cursor":
            require(prior["journal_id"] == bounds["journal_id"] and int(prior["next_usn"]) < first
                    and body["reason"] == "saved_cursor_before_retained_or_valid_journal_range", "wrong expired cursor classification")
        else:
            raise AssertionError("unknown checkpoint fault case")
    require(len(fault_cases) == len(set(fault_cases)), "duplicate checkpoint fault cases")
    if args.component_only:
        require(component["durable_journal_reopen_replay_verified"] is True
                and {"mismatched-journal", "ahead-cursor", "malformed-cursor"}.issubset(fault_cases), "native reopened store/cursor faults not exercised")
        report = {"scope": "real native component; owned checkpoint-store faults against unchanged real volume journal",
                  "component_rows_checked": component_rows, "checkpoint_fault_cases": fault_cases,
                  "durable_journal_reopen_replay_verified": True,
                  "component_report_sha256": digest(root / "component-report.json"),
                  "endpoint_runtime_retested": False, "journal_rotation_or_retention_fault_induced": False,
                  "full_qualification": False}
        target = root / "usn-cursor-verification-report.json"; require(not target.exists(), "preserve existing report")
        target.write_text(json.dumps(report, indent=2), encoding="utf-8"); print(json.dumps({**report, "report_path": str(target)})); return
    original = root / "recovered-records.ndjson"
    require(digest(original) == digest(root / "reopened-records.ndjson"), "durable originals changed across reopen")
    records = {}; health = []; batches = gaps = rows = count = 0
    with original.open(encoding="utf-8-sig") as file:
        for line in file:
            record = json.loads(line); validator.validate(record)
            require(EndpointRecord.model_validate_json(line).model_dump(mode="json")["data"] == record["data"], "Manager altered original body")
            require(record["record_id"] not in records, "duplicate original record identity")
            records[record["record_id"]] = record; count += 1
            if record["category"] == "filesystem_usn_batch":
                rows += check_batch(record); batches += 1
            if record["category"] == "filesystem_usn_gap":
                require(record["data"]["lost_native_events"] is None and record["data"]["full_file_coverage_verified"] is False, "gap invented exact loss/full coverage")
                gaps += 1
            if record["kind"] == "health":
                health.append(record)
    fixture = load(root / "usn-runtime-fixture-report.json")
    require(fixture["Verified"] is True and fixture["Expected"]["Completed"] is True and fixture["ActorAttributionVerified"] is False,
            "runtime owned native mutation not verified")
    before, after = fixture["Expected"]["BeforeName"], fixture["Expected"]["AfterName"]
    masks = {before: 0, after: 0}; identities = set()
    for match in fixture["MatchingRows"]:
        record = records[match["RecordId"]]; row = match["Entry"]
        require(record["category"] == "filesystem_usn_batch" and row in record["data"]["entries"], "owned fixture row absent from original")
        require(row["filename"] in masks and match["Volume"] == record["data"]["volume"]
                and match["JournalId"] == record["data"]["journal_id"], "owned source scope changed")
        masks[row["filename"]] |= int(row["reason_mask"])
        identities.add((match["Volume"], match["JournalId"], row["file_id_width_bits"], row["file_id_native_bytes_hex"]))
    require(masks[before] & 0x100 and masks[before] & 0x70 and masks[before] & 0x1000
            and masks[after] & 0x2000 and masks[after] & 0x200 and len(identities) == 1, "owned reason/source-file evidence missing or ambiguous")
    active_health = sum(any(v["state"] == "degraded" and int(v["checkpoint_revision"]) > 0
                           for v in r["data"].get("usn_journal", {}).get("volumes", [])) for r in health)
    bindings = 0
    for record in health:
        for volume in record["data"].get("usn_journal", {}).get("volumes", []):
            record_id = volume.get("last_committed_record_id")
            if not record_id:
                continue
            require(record_id in records, "committed USN health record absent")
            body = records[record_id]["data"]
            cursor = body["source_checkpoint_next_cursor"]
            require(body["source"] == volume["source"] and body["volume"] == volume["volume"]
                    and cursor["journal_id"] == volume["journal_id"] and cursor["next_usn"] == volume["committed_next_usn"]
                    and int(body["source_checkpoint_expected_revision"]) + 1 == int(volume["checkpoint_revision"]),
                    "USN health cursor/revision/source binding changed")
            bindings += 1
    require(batches > 0 and gaps > 0 and active_health > 0 and bindings > 0, "native runtime source/health evidence missing")
    report = {"scope": "native USN component and independently exercised endpoint runtime", "component_runs": len(components),
              "component_and_synthetic_rows_checked": component_rows, "synthetic_fixture_records": len(component["synthetic_contract_fixtures"]),
              "schema_and_manager_original_records": count, "runtime_usn_batches": batches, "runtime_usn_gaps": gaps,
              "runtime_usn_rows": rows, "owned_runtime_fixture_rows": len(fixture["MatchingRows"]), "active_source_health_records": active_health,
              "committed_cursor_health_bindings": bindings,
              "create_ads_rename_delete_verified": True, "refused_commit_cursor_verified": True, "stopped_source_replay_verified": True,
              "component_held_file_index_verified": True, "originals_sha256": digest(original), "full_file_coverage_verified": False,
              "process_attribution_verified": False, "full_qualification": False}
    target = root / "usn-verification-report.json"; require(not target.exists(), "preserve existing report")
    target.write_text(json.dumps(report, indent=2), encoding="utf-8"); print(json.dumps({**report, "report_path": str(target)}))


if __name__ == "__main__":
    main()
