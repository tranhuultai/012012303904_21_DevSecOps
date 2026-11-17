#!/usr/bin/env python3
"""Dispatch isolated D/C/N and E3 workflow runs, download small observations, and summarize.

Requires the GitHub CLI (`gh`) authenticated for Actions read/write on this repo.
The script pins every dispatch to one resolved commit and resumes safely by run key.
"""

import argparse
import csv
from contextlib import contextmanager
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


PROJECT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_DIR.parent.parent
GROUND_TRUTH = PROJECT_DIR / "ground_truth" / "ground_truth.csv"
WORKFLOW_FILE = "ci.yml"
RUN_NAME_PREFIX = "DevSecOps CI"
INDEX_LOCK = threading.Lock()


def run_gh(args, *, check=True):
    result = subprocess.run(
        ["gh", *args], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if check and result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"gh {' '.join(args)} failed: {details}")
    return result


def gh_json(args):
    result = run_gh(args)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"GitHub CLI returned invalid JSON: {error}") from error


def repository_name():
    result = run_gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"])
    return result.stdout.strip()


def resolve_commit(repo, ref):
    api_ref = quote(ref, safe="")
    for attempt in range(5):
        try:
            commit = gh_json(["api", f"repos/{repo}/commits/{api_ref}"])
            return commit["sha"]
        except RuntimeError as error:
            if attempt == 4:
                raise
            delay = min(5 * (attempt + 1), 20)
            print(f"GitHub commit lookup failed temporarily: {error}; retrying in {delay}s", flush=True)
            time.sleep(delay)
    raise AssertionError("unreachable")


def fixture_ids():
    with GROUND_TRUTH.open(encoding="utf-8-sig", newline="") as stream:
        return [row["id"].strip().upper() for row in csv.DictReader(stream)]


def normalize_fixture_id(value):
    value = value.strip()
    return "baseline" if value.casefold() == "baseline" else value.upper()


def atomic_write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def matching_runs(runs, fixture_id, cache_mode, benchmark_role, commit_sha,
                  study_id, known_run_ids=()):
    suffix = f"| {fixture_id} | {cache_mode} | {benchmark_role} | {commit_sha} | {study_id}"
    known_run_ids = {int(value) for value in known_run_ids}
    candidates = []
    for run in runs:
        if run.get("event") != "workflow_dispatch" or run.get("headSha") != commit_sha:
            continue
        if not str(run.get("displayTitle", "")).endswith(suffix):
            continue
        if int(run["databaseId"]) in known_run_ids:
            continue
        candidates.append(run)
    return candidates


def list_matching_run(repo, ref, fixture_id, cache_mode, benchmark_role, commit_sha,
                      study_id, known_run_ids=()):
    runs = gh_json([
        "run", "list", "--repo", repo, "--workflow", WORKFLOW_FILE,
        "--branch", ref, "--event", "workflow_dispatch", "--limit", "100",
        "--json", "databaseId,displayTitle,event,status,conclusion,headSha,url,createdAt",
    ])
    # The unique study ID in the run name prevents matching older runs; known
    # IDs additionally protect against a stale run list or accidental replay.
    candidates = matching_runs(
        runs, fixture_id, cache_mode, benchmark_role, commit_sha,
        study_id, known_run_ids,
    )
    return max(candidates, key=lambda item: item["createdAt"]) if candidates else None


def wait_for_run(repo, ref, fixture_id, cache_mode, benchmark_role, commit_sha,
                 study_id, timeout_minutes, known_run_ids=()):
    deadline = time.monotonic() + timeout_minutes * 60
    run_record = None
    while time.monotonic() < deadline:
        try:
            run_record = list_matching_run(
                repo, ref, fixture_id, cache_mode, benchmark_role, commit_sha,
                study_id, known_run_ids,
            )
            if run_record:
                details = gh_json([
                    "run", "view", str(run_record["databaseId"]), "--repo", repo,
                    "--json", "databaseId,status,conclusion,headSha,url,jobs",
                ])
                if details.get("status") == "completed":
                    return details
        except RuntimeError as error:
            print(f"GitHub API polling failed temporarily: {error}; retrying", flush=True)
        time.sleep(20)
    if run_record:
        raise TimeoutError(f"Run {run_record['databaseId']} did not complete within {timeout_minutes} minutes")
    raise TimeoutError(
        f"No workflow run appeared for {fixture_id}/{cache_mode}/{benchmark_role}; "
        "check workflow_dispatch permission and the run-name in ci.yml"
    )


def duration_seconds(start, end):
    try:
        return max(0.0, (parse_iso(end) - parse_iso(start)).total_seconds())
    except (TypeError, ValueError):
        return None


def job_timing(run_details):
    jobs = {}
    conclusions = {}
    scan_intervals = []
    all_intervals = []
    scan_names = {
        "Prepare Trivy and Grype vulnerability DB snapshots",
        "Security scans (collection mode)",
        "iac",
        "image",
    }
    for job in run_details.get("jobs") or []:
        name = job.get("name") or f"job-{job.get('databaseId', 'unknown')}"
        conclusions[name] = job.get("conclusion")
        duration = duration_seconds(job.get("startedAt"), job.get("completedAt"))
        if duration is None:
            continue
        jobs[name] = round(duration, 2)
        interval = (parse_iso(job["startedAt"]), parse_iso(job["completedAt"]))
        all_intervals.append(interval)
        if name in scan_names:
            scan_intervals.append(interval)

    def elapsed(intervals):
        if not intervals:
            return None
        return round((max(end for _, end in intervals) - min(start for start, _ in intervals)).total_seconds(), 2)

    return {
        "job_durations_seconds": jobs,
        "job_conclusions": conclusions,
        "workflow_wall_seconds": elapsed(all_intervals),
        "workflow_runner_minutes": round(sum(jobs.values()) / 60, 3),
        "scan_stage_wall_seconds": elapsed(scan_intervals),
        "scan_stage_runner_minutes": round(sum(jobs[name] for name in scan_names if name in jobs) / 60, 3),
    }


def extract_observation(folder):
    matches = list(folder.rglob("observation.json"))
    if len(matches) != 1:
        return None, f"expected one observation.json, found {len(matches)}"
    try:
        value = json.loads(matches[0].read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        return None, str(error)
    return value, str(matches[0])


def dispatch_case(repo, ref, expected_sha, output_root, fixture_id, cache_mode,
                  benchmark_role, study_id, run_key, timeout_minutes, index):
    actual_sha = resolve_commit(repo, ref)
    if actual_sha != expected_sha:
        raise RuntimeError(
            f"Ref {ref} moved during the study: expected {expected_sha}, found {actual_sha}. "
            "Stop and start a new study so all fixture runs share one commit."
        )

    existing = list_matching_run(
        repo, ref, fixture_id, cache_mode, benchmark_role,
        expected_sha, study_id,
    )
    if existing:
        print(f"Resume: attach {run_key} to existing run {existing['databaseId']}", flush=True)
        details = wait_for_run(
            repo, ref, fixture_id, cache_mode, benchmark_role,
            expected_sha, study_id, timeout_minutes,
        )
    else:
        prior_runs = gh_json([
            "run", "list", "--repo", repo, "--workflow", WORKFLOW_FILE,
            "--branch", ref, "--event", "workflow_dispatch", "--limit", "100",
            "--json", "databaseId",
        ])
        known_run_ids = {int(item["databaseId"]) for item in prior_runs}
        try:
            dispatch = run_gh([
                "workflow", "run", WORKFLOW_FILE, "--repo", repo, "--ref", ref,
                "--field", f"fixture_id={fixture_id}",
                "--field", "run_e4=false",
                "--field", f"cache_mode={cache_mode}",
                "--field", f"benchmark_role={benchmark_role}",
                "--field", f"study_id={study_id}",
            ])
            print(f"Dispatch {run_key}: {dispatch.stdout.strip()}", flush=True)
        except RuntimeError:
            # GitHub can return HTTP 500 after it has created the workflow run.
            # Attach to the exact unique study run before attempting another dispatch.
            existing = list_matching_run(
                repo, ref, fixture_id, cache_mode, benchmark_role,
                expected_sha, study_id,
            )
            if not existing:
                raise
            print(f"Resume: dispatch response failed; attach {run_key} to run {existing['databaseId']}", flush=True)
            known_run_ids = set()

        details = wait_for_run(
            repo, ref, fixture_id, cache_mode, benchmark_role,
            expected_sha, study_id, timeout_minutes, known_run_ids,
        )
    run_id = details["databaseId"]
    artifact_dir = output_root / f"{run_key}-{run_id}"
    artifact_name = f"experiment-{fixture_id}"
    download = run_gh([
        "run", "download", str(run_id), "--repo", repo,
        "--name", artifact_name, "--dir", str(artifact_dir),
    ], check=False)
    # `gh run download` can return non-zero after extracting the complete
    # observation bundle when the archive contains repeated report paths.
    # Treat the artifact as usable when the required observation is present;
    # retain the CLI warning so the extraction quirk remains visible.
    observation, observation_result = extract_observation(artifact_dir)
    downloaded = observation is not None
    download_warning = (download.stderr.strip() or download.stdout.strip()) if download.returncode else None
    timing = job_timing(details)

    g2 = next(
        (result for result in (observation or {}).get("policy_runs", [])
         if result.get("policy") == "g2"),
        {},
    )
    sample_type = "baseline"
    if fixture_id != "baseline":
        with GROUND_TRUTH.open(encoding="utf-8-sig", newline="") as stream:
            sample_type = next(
                (row["type"] for row in csv.DictReader(stream) if row["id"] == fixture_id),
                "unknown",
            )
    conclusion = details.get("conclusion") or "unknown"
    if conclusion == "success":
        classification = "workflow_success"
    elif sample_type == "defect" and g2.get("decision") == "BLOCK":
        classification = "expected_security_block"
    else:
        classification = "workflow_failure_or_unexpected_block"

    entry = {
        "key": run_key,
        "fixture_id": fixture_id,
        "sample_type": sample_type,
        "cache_mode": cache_mode,
        "benchmark_role": benchmark_role,
        "workflow_study_id": study_id,
        "run_id": run_id,
        "run_url": details.get("url"),
        "head_sha": details.get("headSha"),
        "status": details.get("status"),
        "conclusion": conclusion,
        "classification": classification,
        "g2_decision": g2.get("decision"),
        "artifact_name": artifact_name,
        "artifact_path": str(artifact_dir),
        "artifact_downloaded": downloaded,
        "artifact_download_warning": download_warning,
        "observation_status": (observation or {}).get("evidence_status"),
        "observation_path": observation_result if observation else None,
        "observation_error": None if observation else observation_result,
        **timing,
    }
    with INDEX_LOCK:
        index["runs"].append(entry)
    return entry


def existing_keys(index, expected_sha):
    return {
        run["key"] for run in index.get("runs", [])
        if run.get("head_sha") == expected_sha
        and run.get("artifact_downloaded")
        and run.get("observation_status") == "complete"
    }


def run_matrix(args):
    if not shutil.which("gh"):
        raise RuntimeError("GitHub CLI `gh` is required; install it and authenticate with `gh auth login`.")
    auth = run_gh(["auth", "status"], check=False)
    if auth.returncode:
        raise RuntimeError("GitHub CLI is not authenticated. Run `gh auth login` with Actions read/write access.")

    repo = repository_name()
    expected_sha = resolve_commit(repo, args.ref)
    output_root = args.out_dir.resolve()
    fixture_root = output_root / "fixtures"
    e3_root = output_root / "e3"
    index_path = output_root / "run-index.json"
    if args.resume and index_path.is_file():
        index = json.loads(index_path.read_text(encoding="utf-8-sig"))
        if index.get("commit") != expected_sha:
            raise RuntimeError("Existing run-index.json belongs to another commit; use a new output directory.")
    else:
        if output_root.exists() and any(output_root.iterdir()):
            raise RuntimeError(
                f"Output directory is not empty: {output_root}. Use --resume for the same commit "
                "or select a new --out-dir so observations from separate studies are not mixed."
            )
        index = {
            "schema_version": 1,
            "repository": repo,
            "ref": args.ref,
            "commit": expected_sha,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "runs": [],
        }
    study_id = index.get("study_id") or uuid.uuid4().hex[:12]
    index["study_id"] = study_id
    atomic_write_json(index_path, index)

    done = existing_keys(index, expected_sha) if args.resume else set()
    all_cases = ["baseline", *fixture_ids()]
    requested = list(dict.fromkeys(
        normalize_fixture_id(item) for item in args.ids.split(",") if item.strip()
    )) if args.ids else all_cases
    unknown = set(requested) - set(all_cases)
    if unknown:
        raise RuntimeError(f"Unknown fixture IDs: {', '.join(sorted(unknown))}")

    if not args.skip_fixtures:
        pending = [fixture_id for fixture_id in requested if f"fixture-{fixture_id}" not in done]
        # Establish the exact-commit baseline and seed the versioned scanner DB
        # caches before dispatching independent fixture runs concurrently.
        if "baseline" in pending:
            fixture_id = "baseline"
            key = f"fixture-{fixture_id}"
            entry = dispatch_case(
                repo, args.ref, expected_sha, fixture_root, fixture_id,
                args.fixture_cache_mode, "measurement", study_id, key,
                args.timeout_minutes, index,
            )
            atomic_write_json(index_path, index)
            print(f"{fixture_id}: {entry['classification']}, observation={entry['observation_status'] or 'missing'}", flush=True)
            pending.remove("baseline")

        if args.parallelism == 1:
            for fixture_id in pending:
                key = f"fixture-{fixture_id}"
                entry = dispatch_case(
                    repo, args.ref, expected_sha, fixture_root, fixture_id,
                    args.fixture_cache_mode, "measurement", study_id, key,
                    args.timeout_minutes, index,
                )
                atomic_write_json(index_path, index)
                print(f"{fixture_id}: {entry['classification']}, observation={entry['observation_status'] or 'missing'}", flush=True)
        elif pending:
            failures = []
            with ThreadPoolExecutor(max_workers=args.parallelism) as pool:
                future_cases = {
                    pool.submit(
                        dispatch_case,
                        repo, args.ref, expected_sha, fixture_root, fixture_id,
                        args.fixture_cache_mode, "measurement", study_id,
                        f"fixture-{fixture_id}", args.timeout_minutes, index,
                    ): fixture_id
                    for fixture_id in pending
                }
                for future in as_completed(future_cases):
                    fixture_id = future_cases[future]
                    try:
                        entry = future.result()
                    except Exception as error:
                        failures.append(f"{fixture_id}: {error}")
                        print(f"{fixture_id}: ERROR {error}", file=sys.stderr, flush=True)
                    else:
                        print(
                            f"{fixture_id}: {entry['classification']}, "
                            f"observation={entry['observation_status'] or 'missing'}",
                            flush=True,
                        )
                    atomic_write_json(index_path, index)
            if failures:
                raise RuntimeError("One or more fixture runs failed: " + "; ".join(failures))

    if args.e3_warm_repeats:
        key = "e3-warm-cache-prime"
        if key not in done:
            workflow_study_id = f"{study_id}-{key}"
            entry = dispatch_case(
                repo, args.ref, expected_sha, e3_root / "warmup", "baseline",
                "warm", "warmup", workflow_study_id, key, args.timeout_minutes, index,
            )
            entry["study_group_id"] = study_id
            atomic_write_json(index_path, index)
            print(f"Warm cache prime: {entry['classification']}", flush=True)

    for mode, count in (("cold", args.e3_cold_repeats), ("warm", args.e3_warm_repeats)):
        for number in range(1, count + 1):
            key = f"e3-{mode}-{number:02d}"
            if key in done:
                print(f"Resume: skip complete {key}", flush=True)
                continue
            workflow_study_id = f"{study_id}-{key}"
            entry = dispatch_case(
                repo, args.ref, expected_sha, e3_root / mode, "baseline",
                mode, "measurement", workflow_study_id, key, args.timeout_minutes, index,
            )
            entry["study_group_id"] = study_id
            atomic_write_json(index_path, index)
            print(f"{key}: {entry['classification']}, wall={entry['workflow_wall_seconds']}s", flush=True)

    atomic_write_json(index_path, index)
    summary_failures = []
    if not args.skip_fixtures and "baseline" in requested:
        metrics_dir = output_root / "metrics" / "e1-e2-live"
        analysis = subprocess.run([
            sys.executable, str(PROJECT_DIR / "tests" / "analyze_fixture_observations.py"),
            "--input-dir", str(fixture_root), "--out-dir", str(metrics_dir),
        ], cwd=REPO_ROOT, text=True)
        if analysis.returncode:
            summary_failures.append(f"E1/E2 analyzer exited {analysis.returncode}")

    if args.e3_cold_repeats or args.e3_warm_repeats:
        metrics_dir = output_root / "metrics" / "e3-live"
        summary = subprocess.run([
            sys.executable, str(PROJECT_DIR / "tests" / "summarize_e3_live.py"),
            "--run-index", str(index_path), "--out-dir", str(metrics_dir),
        ], cwd=REPO_ROOT, text=True)
        if summary.returncode:
            summary_failures.append(f"E3 analyzer exited {summary.returncode}")

    print(f"\nRun index: {index_path}")
    print(f"Artifacts: {output_root}")
    if summary_failures:
        print("\nEvidence is still incomplete:")
        for message in summary_failures:
            print(f"- {message}")
        return 2
    return 0


@contextmanager
def study_lock(path):
    """Prevent two controllers from dispatching duplicate work to one study."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            handle.write(b"\0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    except OSError as error:
        if not locked:
            raise RuntimeError(
                f"A study controller already holds {path}; stop it or use another --out-dir."
            ) from error
        raise
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="main", help="GitHub branch or tag to freeze for the study")
    parser.add_argument("--out-dir", type=Path, default=PROJECT_DIR / "tests" / "results" / "live-study")
    parser.add_argument("--ids", help="Comma-separated fixture IDs; default is baseline plus every D/C/N fixture")
    parser.add_argument("--fixture-cache-mode", choices=("cold", "warm"), default="cold")
    parser.add_argument(
        "--parallelism", type=int, default=4,
        help="Maximum concurrent D/C/N workflow runs after the baseline; set 1 for sequential runs",
    )
    parser.add_argument("--e3-cold-repeats", type=int, default=0)
    parser.add_argument("--e3-warm-repeats", type=int, default=0)
    parser.add_argument("--timeout-minutes", type=int, default=90)
    parser.add_argument("--resume", action="store_true", help="Skip completed run keys already in run-index.json")
    parser.add_argument("--skip-fixtures", action="store_true", help="Run only the requested E3 baseline repeats")
    args = parser.parse_args()
    if args.e3_cold_repeats < 0 or args.e3_warm_repeats < 0:
        parser.error("E3 repeat counts must not be negative")
    if args.parallelism < 1:
        parser.error("--parallelism must be at least 1")
    output_root = args.out_dir.resolve()
    lock_path = output_root.with_name(f".{output_root.name}.lock")
    try:
        with study_lock(lock_path):
            return run_matrix(args)
    except (RuntimeError, TimeoutError, OSError, KeyError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
