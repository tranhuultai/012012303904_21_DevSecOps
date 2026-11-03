#!/usr/bin/env python3
"""Estimate runner spend from observed job durations and an explicit rate.

This is a transparent planning estimate, not a GitHub invoice calculator.
It excludes billing-minute rounding, included quotas, storage, and network fees.
"""

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timing", required=True, type=Path, help="E3 timing summary JSON")
    parser.add_argument("--rate-usd-per-runner-minute", required=True, type=float)
    parser.add_argument("--runs-per-month", required=True, type=int)
    parser.add_argument("--rate-source", required=True, help="URL or dated pricing note")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    if not math.isfinite(args.rate_usd_per_runner_minute) or args.rate_usd_per_runner_minute < 0:
        parser.error("runner-minute rate must be a finite non-negative number")
    if args.runs_per_month < 0:
        parser.error("runs per month must be non-negative")

    try:
        timing = json.loads(args.timing.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"cannot read timing summary: {error}")

    durations = timing.get("job_durations_seconds") if isinstance(timing, dict) else None
    if not isinstance(durations, dict) or not durations:
        parser.error("timing summary must contain a non-empty job_durations_seconds object")
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(value) or value < 0
        for value in durations.values()
    ):
        parser.error("job durations must be finite non-negative numbers")

    total_minutes = sum(durations.values()) / 60.0
    cost_per_run = total_minutes * args.rate_usd_per_runner_minute
    record = {
        "schema_version": 1,
        "estimate_type": "runner-minutes approximation",
        "source_run_url": timing.get("run_url", ""),
        "source_commit": timing.get("commit", ""),
        "source_evidence_status": timing.get("evidence_status", "unknown"),
        "job_durations_seconds": durations,
        "total_runner_minutes_per_run": round(total_minutes, 4),
        "parallel_critical_path_seconds": timing.get("parallel_scan_stage_critical_path_seconds"),
        "rate_usd_per_runner_minute": args.rate_usd_per_runner_minute,
        "rate_source": args.rate_source,
        "runs_per_month": args.runs_per_month,
        "estimated_usd_per_run": round(cost_per_run, 4),
        "estimated_usd_per_month": round(cost_per_run * args.runs_per_month, 2),
        "calculated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": [
            "Planning estimate only; not an invoice calculation.",
            "Excludes billing-minute rounding, included quotas, storage, and network fees.",
            "Uses observed job runner-minutes; parallel critical path is reported separately.",
            "Pricing rate and monthly run count are explicit user-provided assumptions.",
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Estimated ${record['estimated_usd_per_run']:.4f}/run and ${record['estimated_usd_per_month']:.2f}/month")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
