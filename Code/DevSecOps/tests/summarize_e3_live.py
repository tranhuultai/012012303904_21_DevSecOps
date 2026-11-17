#!/usr/bin/env python3
"""Summarize controlled E3 GitHub Actions runs by cold/warm pip-cache profile."""

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


MIN_RUNS_PER_PROFILE = 5


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def percentile(values, p):
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p / 100
    low = math.floor(rank)
    high = math.ceil(rank)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def stats(values):
    if not values:
        return {"N": 0, "median": None, "q1": None, "q3": None, "iqr": None, "p90": None}
    q1 = percentile(values, 25)
    q3 = percentile(values, 75)
    return {
        "N": len(values),
        "median": round(percentile(values, 50), 2),
        "q1": round(q1, 2),
        "q3": round(q3, 2),
        "iqr": round(q3 - q1, 2),
        "p90": round(percentile(values, 90), 2),
    }


def load_index(path):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise ValueError(f"{path} must contain an object with a runs array")
    return data


def load_observation(run, root):
    candidate = run.get("observation_path")
    if candidate:
        path = Path(candidate)
        if not path.is_absolute():
            path = root / path
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                return value if isinstance(value, dict) else None
            except (OSError, json.JSONDecodeError):
                return None
    artifact_path = run.get("artifact_path")
    if artifact_path:
        root_path = Path(artifact_path)
        if not root_path.is_absolute():
            root_path = root / root_path
        for path in root_path.rglob("observation.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8-sig"))
                if isinstance(value, dict):
                    return value
            except (OSError, json.JSONDecodeError):
                continue
    return None


def build_report(index, index_path):
    root = index_path.parent
    included = []
    excluded = []
    for run in index["runs"]:
        if not str(run.get("key", "")).startswith("e3-"):
            continue
        if run.get("fixture_id") != "baseline":
            continue
        if run.get("benchmark_role", "measurement") == "warmup":
            excluded.append({"run_id": run.get("run_id"), "reason": "warm-up run"})
            continue
        observation = load_observation(run, root)
        if not observation or observation.get("evidence_status") != "complete":
            excluded.append({"run_id": run.get("run_id"), "reason": "missing or incomplete observation"})
            continue
        if observation.get("fixture_id") != "baseline":
            excluded.append({"run_id": run.get("run_id"), "reason": "observation is not baseline"})
            continue
        if observation.get("commit") != run.get("head_sha"):
            excluded.append({"run_id": run.get("run_id"), "reason": "index and observation commits differ"})
            continue
        if observation.get("cache_mode") != run.get("cache_mode"):
            excluded.append({"run_id": run.get("run_id"), "reason": "index and observation cache modes differ"})
            continue
        if observation.get("benchmark_role", "measurement") != run.get("benchmark_role", "measurement"):
            excluded.append({"run_id": run.get("run_id"), "reason": "index and observation benchmark roles differ"})
            continue
        if not all(isinstance(run.get(field), (int, float)) for field in (
            "workflow_wall_seconds", "workflow_runner_minutes",
            "scan_stage_wall_seconds", "scan_stage_runner_minutes",
        )):
            excluded.append({"run_id": run.get("run_id"), "reason": "missing complete timing metrics"})
            continue
        required_pipeline_jobs = {
            "Run Python tests",
            "Prepare Trivy and Grype vulnerability DB snapshots",
            "Security scans (collection mode)",
            "iac",
            "image",
            "gate (Conftest Rego)",
        }
        if not required_pipeline_jobs.issubset((run.get("job_durations_seconds") or {}).keys()):
            excluded.append({"run_id": run.get("run_id"), "reason": "missing one or more pipeline job durations"})
            continue
        job_conclusions = run.get("job_conclusions") or {}
        required_success_jobs = required_pipeline_jobs - {"gate (Conftest Rego)"}
        if not required_pipeline_jobs.issubset(job_conclusions):
            excluded.append({"run_id": run.get("run_id"), "reason": "missing pipeline job conclusions"})
            continue
        if any(job_conclusions.get(name) != "success" for name in required_success_jobs):
            excluded.append({"run_id": run.get("run_id"), "reason": "a test, DB preparation, or scanner job did not succeed"})
            continue
        gate_name = "gate (Conftest Rego)"
        if run.get("conclusion") == "success" and job_conclusions.get(gate_name) == "success":
            completion_basis = "workflow_success"
        else:
            failed_jobs = {name for name, value in job_conclusions.items() if value == "failure"}
            statuses_are_expected = all(value in {"success", "failure", "skipped"} for value in job_conclusions.values())
            expected_gate_block = (
                run.get("conclusion") == "failure"
                and failed_jobs == {gate_name}
                and job_conclusions.get(gate_name) == "failure"
                and isinstance(observation.get("gate"), dict)
                and observation["gate"].get("decision") == "BLOCK"
                and statuses_are_expected
            )
            if not expected_gate_block:
                excluded.append({"run_id": run.get("run_id"), "reason": "workflow failed outside the expected baseline gate block"})
                continue
            completion_basis = "expected_baseline_gate_block"
        run = dict(run)
        run["observation"] = observation
        run["completion_basis"] = completion_basis
        included.append(run)

    by_profile = defaultdict(list)
    for run in included:
        by_profile[run.get("cache_mode", "cold")].append(run)

    profiles = {}
    for mode in ("cold", "warm"):
        records = by_profile.get(mode, [])
        workflow_wall = [r["workflow_wall_seconds"] for r in records if isinstance(r.get("workflow_wall_seconds"), (int, float))]
        workflow_runner = [r["workflow_runner_minutes"] for r in records if isinstance(r.get("workflow_runner_minutes"), (int, float))]
        scan_wall = [r["scan_stage_wall_seconds"] for r in records if isinstance(r.get("scan_stage_wall_seconds"), (int, float))]
        scan_runner = [r["scan_stage_runner_minutes"] for r in records if isinstance(r.get("scan_stage_runner_minutes"), (int, float))]
        job_names = sorted({name for r in records for name in (r.get("job_durations_seconds") or {})})
        per_job = {}
        for name in job_names:
            values = []
            skipped_runs = 0
            for run in records:
                conclusion = (run.get("job_conclusions") or {}).get(name)
                duration = (run.get("job_durations_seconds") or {}).get(name)
                if conclusion == "skipped":
                    skipped_runs += 1
                elif isinstance(duration, (int, float)):
                    values.append(duration)
            per_job[name] = {
                **stats(values),
                "total_runs": len(records),
                "skipped_runs": skipped_runs,
            }
        commits = sorted({r.get("head_sha") for r in records if r.get("head_sha")})
        version_sets = {
            json.dumps(r["observation"].get("tool_versions_configured", {}), sort_keys=True)
            for r in records
        }
        db_snapshots = sorted({
            json.dumps({
                key: meta.get(key)
                for key in ("version", "updated_at", "next_update")
                if meta.get(key) is not None
            }, sort_keys=True)
            for r in records
            for name, meta in (
                r["observation"].get("trivy_runtime", {})
                .get("security-scan", {}).get("databases", {}).items()
            )
            if "vulnerability" in name.casefold()
            and isinstance(meta, dict) and meta.get("updated_at")
        })
        snapshot_ids = sorted({
            str(r["observation"].get("trivy_db_snapshot_id"))
            for r in records if r["observation"].get("trivy_db_snapshot_id")
        })
        grype_db_snapshots = set()
        grype_snapshot_ids = set()
        grype_db_observation_count = 0
        for run in records:
            runtime = run["observation"].get("grype_runtime", {})
            if not isinstance(runtime, dict):
                continue
            snapshot_id = runtime.get("db_snapshot_id")
            if snapshot_id:
                grype_snapshot_ids.add(str(snapshot_id))
            database = runtime.get("db")
            if runtime.get("image_scan_skipped") or not isinstance(database, dict):
                continue
            grype_db_observation_count += 1
            fingerprint = {
                "grype_version": runtime.get("grype_version"),
                "db_snapshot_id": snapshot_id,
                **{
                    key: database.get(key)
                    for key in ("schema_version", "built", "from", "valid")
                },
            }
            grype_db_snapshots.add(json.dumps(fingerprint, sort_keys=True))
        grype_db_snapshots = sorted(grype_db_snapshots)
        grype_snapshot_ids = sorted(grype_snapshot_ids)
        profiles[mode] = {
            "N": len(records),
            "run_ids": [r.get("run_id") for r in records],
            "commits": commits,
            "tool_version_sets": len(version_sets),
            "tool_version_fingerprints": sorted(version_sets),
            "trivy_db_snapshots": db_snapshots,
            "trivy_db_snapshot_ids": snapshot_ids,
            "grype_db_snapshots": grype_db_snapshots,
            "grype_db_snapshot_ids": grype_snapshot_ids,
            "grype_db_observation_count": grype_db_observation_count,
            "expected_baseline_gate_block_runs": sum(
                run.get("completion_basis") == "expected_baseline_gate_block" for run in records
            ),
            "workflow_wall_seconds": stats(workflow_wall),
            "workflow_runner_minutes": stats(workflow_runner),
            "scan_stage_wall_seconds": stats(scan_wall),
            "scan_stage_runner_minutes": stats(scan_runner),
            "per_job_seconds": per_job,
        }

    same_commit = (
        len(profiles["cold"]["commits"]) == 1
        and profiles["cold"]["commits"] == profiles["warm"]["commits"]
        and len(profiles["warm"]["commits"]) == 1
    )
    versions_match = (
        len(profiles["cold"]["tool_version_fingerprints"]) == 1
        and len(profiles["warm"]["tool_version_fingerprints"]) == 1
        and profiles["cold"]["tool_version_fingerprints"]
        == profiles["warm"]["tool_version_fingerprints"]
    )
    enough_repeats = all(profiles[mode]["N"] >= MIN_RUNS_PER_PROFILE for mode in ("cold", "warm"))
    cold_db = set(profiles["cold"]["trivy_db_snapshots"])
    warm_db = set(profiles["warm"]["trivy_db_snapshots"])
    cold_snapshot_ids = set(profiles["cold"]["trivy_db_snapshot_ids"])
    warm_snapshot_ids = set(profiles["warm"]["trivy_db_snapshot_ids"])
    snapshot_ids_match = (
        len(cold_snapshot_ids) == 1
        and cold_snapshot_ids == warm_snapshot_ids
        and len(warm_snapshot_ids) == 1
    )
    cold_grype_db = set(profiles["cold"]["grype_db_snapshots"])
    warm_grype_db = set(profiles["warm"]["grype_db_snapshots"])
    cold_grype_ids = set(profiles["cold"]["grype_db_snapshot_ids"])
    warm_grype_ids = set(profiles["warm"]["grype_db_snapshot_ids"])
    grype_snapshot_ids_match = (
        len(cold_grype_ids) == 1
        and cold_grype_ids == warm_grype_ids
        and len(warm_grype_ids) == 1
    )
    grype_database_snapshots_match = (
        bool(cold_grype_db) and cold_grype_db == warm_grype_db and len(cold_grype_db) == 1
        and grype_snapshot_ids_match
        and profiles["cold"]["grype_db_observation_count"] == profiles["cold"]["N"]
        and profiles["warm"]["grype_db_observation_count"] == profiles["warm"]["N"]
    )
    trivy_database_snapshots_match = bool(cold_db) and cold_db == warm_db and len(cold_db) == 1
    database_snapshots_match = trivy_database_snapshots_match and snapshot_ids_match and grype_database_snapshots_match
    complete = same_commit and versions_match and enough_repeats and database_snapshots_match
    cold_median = profiles["cold"]["workflow_wall_seconds"]["median"]
    warm_median = profiles["warm"]["workflow_wall_seconds"]["median"]
    delta = None
    if cold_median is not None and warm_median is not None:
        warm_minus_cold = round(warm_median - cold_median, 2)
        direction = "nhanh hơn" if warm_minus_cold < 0 else "chậm hơn" if warm_minus_cold > 0 else "ngang nhau"
        delta = {
            "warm_minus_cold_seconds": warm_minus_cold,
            "warm_change_percent": round((warm_median - cold_median) / cold_median * 100, 2) if cold_median else None,
            "interpretation": f"profile pip cache warm có wall median {direction} profile cold",
        }

    return {
        "experiment": "E3 controlled CI duration",
        "evidence_status": "complete" if complete else "partial",
        "measurement_definition": {
            "workflow_wall_seconds": "min(job.started_at) to max(job.completed_at) for one workflow_dispatch run",
            "workflow_runner_minutes": "sum of measured durations for all completed jobs divided by 60",
            "eligible_completion": "successful workflow, or a complete baseline observation where test/DB/scanner jobs succeeded and the only failed job was G2 gate BLOCK",
            "scan_stage_wall_seconds": "vulnerability DB preparation start to last completion among DB preparation and the parallel security-scan, iac, and image jobs",
            "scan_stage_runner_minutes": "sum of vulnerability DB preparation and the three scanner job durations divided by 60",
            "cache_variable": "actions/setup-python pip cache for pytest/runtime dependencies, Semgrep, and Checkov installations",
            "execution_mode": "parallel scanner jobs; this experiment does not claim a serial-mode comparison",
            "warmup": "runs marked benchmark_role=warmup are excluded from all statistics",
        },
        "acceptance": {
            "minimum_runs_per_profile": MIN_RUNS_PER_PROFILE,
            "same_commit_required": True,
            "pinned_tool_versions_required": True,
            "same_trivy_database_snapshot_required": True,
            "same_grype_database_snapshot_required": True,
            "same_commit": same_commit,
            "tool_versions_consistent": versions_match,
            "enough_repeats": enough_repeats,
            "trivy_database_snapshot_consistent": trivy_database_snapshots_match,
            "trivy_database_snapshot_id_consistent": snapshot_ids_match,
            "grype_database_snapshot_consistent": grype_database_snapshots_match,
            "grype_database_snapshot_id_consistent": grype_snapshot_ids_match,
        },
        "profiles": profiles,
        "cache_comparison": delta,
        "excluded_runs": excluded,
        "limitations": [
            "Cache comparison covers pip package downloads for the test job, Semgrep, and Checkov. Separate versioned immutable Trivy and Grype vulnerability DB caches are shared by both profiles and excluded from the pip-cache variable.",
            "GitHub-hosted runner hardware and external network conditions can vary between runs; report the observed spread.",
            "Wall time is the measured workflow job interval for the dispatch run; release and kind deploy-smoke are skipped on workflow_dispatch.",
            "A run with a blocked baseline gate is retained only when tests, DB preparation, and all scanner jobs succeeded and the gate is the sole failed job; other workflow failures are excluded.",
            "A complete cache comparison requires one shared Trivy and Grype vulnerability DB snapshot across both profiles; the workflow records both snapshot keys and runtime DB metadata.",
        ],
    }


def markdown(report):
    lines = [
        "# E3 – Thời gian CI theo cache profile",
        "",
        f"**Trạng thái bằng chứng:** `{report['evidence_status']}`",
        "",
        "| Cache pip | N hợp lệ | Lượt G2 chặn baseline | Wall median (s) | Wall IQR (s) | Wall p90 (s) | Tổng runner-minutes median | Scan stage median (s) | Scan runner-minutes median |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in ("cold", "warm"):
        profile = report["profiles"][mode]
        wall = profile["workflow_wall_seconds"]
        runner = profile["workflow_runner_minutes"]
        scan = profile["scan_stage_wall_seconds"]
        minutes = profile["scan_stage_runner_minutes"]
        fmt = lambda value, suffix="": "chưa đo" if value is None else f"{value}{suffix}"
        lines.append(
            f"| {mode} | {profile['N']} | {profile['expected_baseline_gate_block_runs']} | "
            f"{fmt(wall['median'])} | {fmt(wall['iqr'])} | "
            f"{fmt(wall['p90'])} | {fmt(runner['median'])} | {fmt(scan['median'])} | {fmt(minutes['median'])} |"
        )
    lines.extend(["", "## Thời gian từng job", "", "| Cache | Job | N đo được | Median (s) | IQR (s) | p90 (s) |", "|---|---|---:|---:|---:|---:|"])
    for mode in ("cold", "warm"):
        for name, value in report["profiles"][mode]["per_job_seconds"].items():
            entirely_skipped = value["N"] == 0 and value["skipped_runs"] == value["total_runs"]
            if entirely_skipped:
                lines.append(f"| {mode} | {name} (skipped) | — | — | — | — |")
            else:
                label = f"{name} (skipped {value['skipped_runs']}/{value['total_runs']})" if value["skipped_runs"] else name
                lines.append(f"| {mode} | {label} | {value['N']} | {value['median']} | {value['iqr']} | {value['p90']} |")
    comparison = report.get("cache_comparison")
    lines.extend(["", "## So sánh cache", ""])
    if comparison:
        difference = comparison["warm_minus_cold_seconds"]
        direction = "chậm hơn" if difference > 0 else "nhanh hơn" if difference < 0 else "ngang nhau"
        lines.append(
            f"- Warm có median wall **{abs(difference)} giây {direction}** cold "
            f"({comparison['warm_change_percent']:+.2f}%). {comparison['interpretation']}."
        )
    else:
        lines.append("Chưa đủ lượt đo ở cả hai profile để tính chênh lệch.")
    lines.extend(["", "## Điều kiện và giới hạn", ""])
    for item in report["limitations"]:
        lines.append(f"- {item}")
    if report["excluded_runs"]:
        lines.extend(["", f"Số run bị loại: **{len(report['excluded_runs'])}**."])
    return "\n".join(lines) + "\n"


def main():
    # The report contains Vietnamese text; PowerShell may launch Python with
    # the legacy cp1252 console encoding even though the UTF-8 files were
    # written successfully. Keep the CLI summary from failing after report
    # generation on Windows.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-index", required=True, type=Path, help="run-index.json from run_fixture_matrix.py")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        index = load_index(args.run_index)
        report = build_report(index, args.run_index)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "e3_live_cache_comparison.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.out_dir / "e3_live_cache_comparison.md").write_text(markdown(report), encoding="utf-8")
    print(markdown(report))
    return 0 if report["evidence_status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
