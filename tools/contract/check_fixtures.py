#!/usr/bin/env python3
"""CTest driver: generate canonical fixtures with officer-contract-fixtures and
validate them against panopticon-contracts in current-producer mode.

    check_fixtures.py --generator EXE --contracts DIR --out DIR

Exit 0 conforms, 1 contract violation, 77 skipped (Python jsonschema or the
contracts checkout is unavailable; CTest reports SKIP, never PASS).
"""

import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

SKIP = 77


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", required=True, type=Path)
    parser.add_argument("--contracts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    validator = args.contracts / "scripts" / "endpoint_records.py"
    if not validator.is_file():
        print(f"SKIP: contracts checkout not found at {args.contracts}")
        return SKIP
    if importlib.util.find_spec("jsonschema") is None:
        print("SKIP: Python package 'jsonschema' is not installed")
        return SKIP
    if args.out.exists():
        shutil.rmtree(args.out)
    generated = subprocess.run([str(args.generator), str(args.out)])
    if generated.returncode != 0:
        print("FAIL: fixture generator refused to build a family")
        return 1
    return subprocess.run([sys.executable, str(validator), "--current-producer", str(args.out)]).returncode


if __name__ == "__main__":
    sys.exit(main())
