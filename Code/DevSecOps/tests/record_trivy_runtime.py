#!/usr/bin/env python3
"""Capture Trivy and vulnerability database versions after the SCA scan."""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    record = {"trivy_version": None, "databases": {}, "error": None}
    binary = shutil.which("trivy")
    if not binary:
        record["error"] = "trivy executable is not available"
    else:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode:
            record["error"] = f"trivy --version exited with {result.returncode}"
        else:
            section = None
            for line in output.splitlines():
                stripped = line.strip()
                if not line[:1].isspace() and stripped.endswith(":"):
                    section = stripped[:-1]
                    continue
                match = re.match(r"^Version:\s*(\S+)", stripped)
                if section is None and match:
                    record["trivy_version"] = match.group(1)
                    continue
                if section and section != "Version" and match:
                    record["databases"].setdefault(section, {})["version"] = match.group(1)
                    continue
                if section and section != "Version":
                    match = re.match(r"^(UpdatedAt|NextUpdate):\s*(.+)$", stripped)
                    if match:
                        key = "updated_at" if match.group(1) == "UpdatedAt" else "next_update"
                        record["databases"].setdefault(section, {})[key] = match.group(2).strip()
            if not record["trivy_version"]:
                record["error"] = "could not parse Trivy version output"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote Trivy runtime metadata: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
