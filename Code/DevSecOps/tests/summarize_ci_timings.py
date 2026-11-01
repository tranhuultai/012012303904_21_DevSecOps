#!/usr/bin/env python3
"""Summarize traceable per-job timings downloaded from one Actions run."""

import argparse
import json
import statistics
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    records = []
    for path in sorted(input_dir.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip invalid timing record {path}: {error}", file=sys.stderr)
            continue
        if not isinstance(record, dict) or not isinstance(record.get("duration_seconds"), int):
            continue
        records.append(record)

    required_jobs = {"security-scan", "iac", "image"}
    jobs = {record.get("job") for record in records}
    missing = sorted(required_jobs - jobs)
    if missing:
        print(f"No complete timing set; missing: {', '.join(missing)}")
        return 0

    ids = {(r.get("run_id"), r.get("run_attempt")) for r in records}
    commits = {r.get("commit") for r in records}
    if len(ids) != 1 or len(commits) != 1:
        print("Timing files refer to different workflow attempts or commits; not combining.", file=sys.stderr)
        return 1

    selected = [r for r in records if r.get("job") in required_jobs]
    durations = {r["job"]: r["duration_seconds"] for r in selected}
    run_url = next((r.get("run_url") for r in selected if r.get("run_url")), "")
    result = {
        "evidence_status": "traceable_single_run",
        "run_id": selected[0].get("run_id"),
        "run_attempt": selected[0].get("run_attempt"),
        "run_url": run_url,
        "commit": selected[0].get("commit"),
        "job_durations_seconds": durations,
        "parallel_scan_stage_critical_path_seconds": max(durations.values()),
        "serial_sum_estimate_seconds": sum(durations.values()),
        "interpretation": (
            "Observed timings for three scanner jobs in one workflow run. "
            "The max is their parallel critical-path estimate; the sum is a "
            "serial-work estimate, not a measured serial run. Repeated runs "
            "and cache-on/off comparison are still required."
        ),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote traceable timing summary: {out} ({statistics.median(durations.values())}s median job)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
