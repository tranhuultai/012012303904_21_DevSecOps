#!/usr/bin/env python3
"""Apply one committed Dxx/Cxx/Nxx experiment patch to this checkout safely."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


CASE_ID = re.compile(r"^[DCN][0-9]{2}$")
PROJECT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_DIR.parent.parent
PATCH_DIR = PROJECT_DIR / "ground_truth" / "patches"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="baseline or a patch ID such as D01/C01/N01")
    args = parser.parse_args()
    case_id = args.id.strip().upper()

    if case_id == "BASELINE":
        print("Using repository baseline (no fixture patch applied).")
        return 0
    if not CASE_ID.fullmatch(case_id):
        parser.error("fixture ID must be baseline or a Dxx/Cxx/Nxx identifier")

    matches = sorted(PATCH_DIR.glob(f"{case_id}_*.patch"))
    if len(matches) != 1:
        print(f"Expected exactly one patch for {case_id}; found {len(matches)}", file=sys.stderr)
        return 2

    patch = matches[0]
    check = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "apply", "--check", str(patch)],
        text=True,
        capture_output=True,
    )
    if check.returncode:
        print(f"Patch {case_id} does not apply cleanly:\n{check.stderr}", file=sys.stderr)
        return check.returncode

    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "apply", str(patch)],
        text=True,
        capture_output=True,
    )
    if result.returncode:
        print(f"Could not apply patch {case_id}:\n{result.stderr}", file=sys.stderr)
        return result.returncode

    print(f"Applied fixture {case_id} from {patch.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
