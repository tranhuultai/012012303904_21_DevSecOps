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
    fixtures = {r.get("fixture_id", "baseline") for r in records}
    cache_modes = {r.get("cache_mode", "cold") for r in records}
    benchmark_roles = {r.get("benchmark_role", "measurement") for r in records}
    execution_modes = {r.get("scan_execution_mode", "parallel") for r in records}
    runner_profiles = {(r.get("runner_os"), r.get("runner_arch")) for r in records}
    if (len(ids) != 1 or len(commits) != 1 or len(fixtures) != 1
            or len(cache_modes) != 1 or len(benchmark_roles) != 1
            or len(execution_modes) != 1 or len(runner_profiles) != 1):
        print(
            "Timing files refer to different workflow attempts, commits, fixtures, "
            "cache modes, benchmark roles, execution modes, or runner profiles; not combining.",
            file=sys.stderr,
        )
        return 1

    selected = [r for r in records if r.get("job") in required_jobs]
    durations = {r["job"]: r["duration_seconds"] for r in selected}
    run_url = next((r.get("run_url") for r in selected if r.get("run_url")), "")
    starts = [r["started_at"] for r in selected if r.get("started_at")]
    ends = [r["ended_at"] for r in selected if r.get("ended_at")]
    runner_os, runner_arch = next(iter(runner_profiles))
    result = {
        "evidence_status": "traceable_single_run",
        "run_id": selected[0].get("run_id"),
        "run_attempt": selected[0].get("run_attempt"),
        "run_url": run_url,
        "commit": selected[0].get("commit"),
        "fixture_id": selected[0].get("fixture_id", "baseline"),
        "cache_mode": selected[0].get("cache_mode", "cold"),
        "benchmark_role": selected[0].get("benchmark_role", "measurement"),
        "scan_execution_mode": selected[0].get("scan_execution_mode", "parallel"),
        "runner_os": runner_os,
        "runner_arch": runner_arch,
        "scan_stage_started_at": min(starts) if starts else "",
        "scan_stage_ended_at": max(ends) if ends else "",
        "job_durations_seconds": durations,
        "scan_stage_runner_minutes": round(sum(durations.values()) / 60, 3),
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
