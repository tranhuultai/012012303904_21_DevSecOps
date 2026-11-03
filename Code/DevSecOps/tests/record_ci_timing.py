#!/usr/bin/env python3
"""Write traceable wall-clock timing for one GitHub Actions job."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    parser.add_argument("--started-at-epoch", required=True, type=int)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    ended = int(datetime.now(tz=timezone.utc).timestamp())
    if args.started_at_epoch > ended:
        print("job start time is in the future", file=sys.stderr)
        return 2

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_url = f"{server}/{repository}/actions/runs/{run_id}" if run_id and repository else ""
    if run_url and attempt:
        run_url += f"/attempts/{attempt}"

    record = {
        "schema_version": 1,
        "job": args.job,
        "run_id": run_id,
        "run_attempt": attempt,
        "run_url": run_url,
        "commit": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "fixture_id": os.environ.get("FIXTURE_ID", "baseline"),
        "started_at": utc_iso(args.started_at_epoch),
        "ended_at": utc_iso(ended),
        "duration_seconds": ended - args.started_at_epoch,
        "runner_os": os.environ.get("RUNNER_OS", ""),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {args.job}: {record['duration_seconds']}s ({run_url or 'no GitHub run URL'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
