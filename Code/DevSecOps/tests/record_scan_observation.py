#!/usr/bin/env python3
"""Record traceable metadata for one real CI scanner/gate run.

The record stores normalized finding summaries and hashes of raw reports, not
raw scanner contents. Raw files are uploaded separately as a workflow artifact.
"""

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


RAW_REPORTS = (
    "semgrep.json",
    "gitleaks.json",
    "trivy.json",
    "checkov.json",
    "checkov.stream.json",
    "trivy-config.json",
    "grype-image.json",
    "conftest-workflow.json",
)
E4_RAW_REPORTS = (
    "raw/e4/trivy-image-before.json",
    "raw/e4/trivy-image-after.json",
    "raw/e4/sbom-before.cdx.json",
    "raw/e4/sbom-after.cdx.json",
)

TOOL_VERSION_ENV = {
    "semgrep": "SEMGREP_VERSION",
    "gitleaks": "GITLEAKS_VERSION",
    "trivy": "TRIVY_VERSION",
    "checkov": "CHECKOV_VERSION",
    "syft": "SYFT_VERSION",
    "grype": "GRYPE_VERSION",
    "conftest": "CONFTEST_VERSION",
}


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except (OSError, json.JSONDecodeError) as error:
        return None, str(error)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True, type=Path)
    parser.add_argument("--gate-report", required=True, type=Path)
    parser.add_argument("--timing-summary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    issues = []
    raw_reports = {}
    for name in RAW_REPORTS:
        path = args.reports_dir / name
        if not path.is_file():
            raw_reports[name] = {"present": False}
            issues.append(f"missing raw report: {name}")
            continue
        try:
            contents = path.read_bytes()
        except OSError as error:
            raw_reports[name] = {"present": False, "error": str(error)}
            issues.append(f"cannot read raw report {name}: {error}")
            continue
        raw_reports[name] = {
            "present": True,
            "size_bytes": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(),
        }
        if not contents.strip():
            issues.append(f"empty raw report: {name}")

    fixture_id = os.environ.get("FIXTURE_ID", "baseline")
    run_e4_requested = (
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and fixture_id == "baseline"
        and os.environ.get("RUN_E4", "false").casefold() == "true"
    )
    e4_report_states = {}
    for name in E4_RAW_REPORTS:
        path = args.reports_dir / name
        present = path.is_file()
        e4_report_states[name] = {"present": present}
        if present:
            contents = path.read_bytes()
            e4_report_states[name].update({
                "size_bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
            })
    e4_summary_path = args.reports_dir / "e4" / "e4_image_remediation.json"
    e4_summary, e4_error = load_json(e4_summary_path) if e4_summary_path.is_file() else (None, "missing")
    e4_complete = (
        run_e4_requested
        and all(value["present"] for value in e4_report_states.values())
        and not e4_error
        and isinstance(e4_summary, dict)
        and e4_summary.get("evidence_status") == "comparable"
        and e4_summary.get("causal_attribution_allowed") is True
    )
    e4_evidence_status = (
        "not_requested" if not run_e4_requested
        else "complete" if e4_complete
        else "incomplete"
    )

    normalized, error = load_json(args.reports_dir / "normalized_findings.json")
    if error:
        issues.append(f"invalid normalized findings: {error}")
    if not isinstance(normalized, list):
        issues.append("normalized findings missing or not an array")
        normalized = []

    findings = [item for item in normalized if isinstance(item, dict)]
    by_tool = Counter(str(item.get("tool", "unknown")) for item in findings)
    by_severity = Counter(str(item.get("severity", "unknown")) for item in findings)

    gate, error = load_json(args.gate_report)
    if error:
        issues.append(f"invalid gate report: {error}")
    if not isinstance(gate, dict) or gate.get("decision") not in {"PASS", "WARN", "BLOCK"}:
        issues.append("gate report missing or has an invalid decision")
        gate_summary = None
    else:
        gate_summary = {
            "policy": gate.get("policy_profile"),
            "decision": gate.get("decision"),
            "summary": gate.get("summary", {}),
        }

    policy_runs = []
    for policy in ("g0", "g1", "g2"):
        path = args.reports_dir / "experiment" / f"gate-report-{policy}.json"
        if not path.is_file():
            continue
        report, error = load_json(path)
        if error or not isinstance(report, dict):
            issues.append(f"invalid {policy} experiment gate report: {error or 'not an object'}")
            continue
        if not isinstance(report.get("blockers"), list):
            issues.append(f"{policy} experiment gate report has no blockers array")
        if not isinstance(report.get("warnings"), list):
            issues.append(f"{policy} experiment gate report has no warnings array")
        policy_runs.append({
            "policy": policy,
            "decision": report.get("decision"),
            "summary": report.get("summary", {}),
            "blockers": [
                {
                    "rule_id": item.get("rule_id"),
                    "message": item.get("message"),
                    "file": item.get("file"),
                }
                for item in report.get("blockers", []) if isinstance(report.get("blockers"), list)
                if isinstance(item, dict)
            ],
            "warnings": [
                {
                    "rule_id": item.get("rule_id"),
                    "message": item.get("message"),
                    "file": item.get("file"),
                    "severity": item.get("severity"),
                    "advisory_ids": item.get("advisory_ids", []),
                    "control_ids": item.get("control_ids", []),
                    "affected_findings": [
                        {
                            "tool": affected.get("tool"),
                            "category": affected.get("category"),
                            "title": affected.get("title"),
                            "file": affected.get("file"),
                            "resource": affected.get("resource"),
                            "package": affected.get("package"),
                            "installed_version": affected.get("installed_version"),
                        }
                        for affected in item.get("affected_findings", [])
                        if isinstance(affected, dict)
                    ],
                }
                for item in report.get("warnings", []) if isinstance(report.get("warnings"), list)
                if isinstance(item, dict)
            ],
        })

    timing, error = load_json(args.timing_summary)
    if error:
        issues.append(f"invalid timing summary: {error}")
    if not isinstance(timing, dict):
        timing = None
        issues.append("traceable timing summary missing")
    if timing and timing.get("fixture_id", "baseline") != fixture_id:
        issues.append(
            f"timing fixture {timing.get('fixture_id')} differs from scan fixture {fixture_id}"
        )
    cache_mode = os.environ.get("CACHE_MODE", "cold")
    benchmark_role = os.environ.get("BENCHMARK_ROLE", "measurement")
    execution_mode = os.environ.get("SCAN_EXECUTION_MODE", "parallel")
    if timing:
        for key, expected in (
            ("cache_mode", cache_mode),
            ("benchmark_role", benchmark_role),
            ("scan_execution_mode", execution_mode),
            ("commit", os.environ.get("GITHUB_SHA", "")),
            ("run_id", os.environ.get("GITHUB_RUN_ID", "")),
            ("run_attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "")),
        ):
            if str(timing.get(key, "")) != str(expected):
                issues.append(f"timing {key} differs from workflow setting")
        if not timing.get("scan_stage_started_at") or not timing.get("scan_stage_ended_at"):
            issues.append("timing scan-stage start/end timestamps missing")

    trivy_runtime = {}
    runtime_paths = sorted((args.reports_dir / "experiment").glob("trivy-runtime-*.json"))
    if not runtime_paths:
        issues.append("Trivy runtime metadata missing")
    for runtime_path in runtime_paths:
        runtime, error = load_json(runtime_path)
        job = runtime_path.stem.removeprefix("trivy-runtime-")
        if error or not isinstance(runtime, dict):
            issues.append(f"invalid Trivy runtime metadata for {job}: {error or 'not an object'}")
            continue
        trivy_runtime[job] = runtime
        if runtime.get("trivy_version") != os.environ.get("TRIVY_VERSION"):
            issues.append(f"Trivy runtime version differs from configured version for {job}")
    security_runtime = trivy_runtime.get("security-scan", {})
    vuln_db = next(
        (
            metadata for name, metadata in security_runtime.get("databases", {}).items()
            if "vulnerability" in name.casefold() and isinstance(metadata, dict)
        ),
        {},
    )
    if not vuln_db.get("updated_at"):
        issues.append("Trivy vulnerability database UpdatedAt metadata was not captured")

    skipped_path = args.reports_dir / "experiment" / "skipped-scans.json"
    skipped_record, error = load_json(skipped_path) if skipped_path.is_file() else ({"skipped": []}, None)
    if error or not isinstance(skipped_record, dict) or not isinstance(skipped_record.get("skipped"), list):
        issues.append(f"invalid skipped-scan record: {error or 'expected an object with skipped array'}")
        skipped_scans = []
    else:
        skipped_scans = skipped_record["skipped"]

    grype_report, grype_error = load_json(args.reports_dir / "grype-image.json")
    grype_descriptor = (grype_report or {}).get("descriptor", {}) if isinstance(grype_report, dict) else {}
    grype_db_status = (
        grype_descriptor.get("db", {}).get("status", {})
        if isinstance(grype_descriptor.get("db"), dict)
        else {}
    )
    grype_skipped = "grype-image" in skipped_scans
    grype_runtime = {
        "grype_version": grype_descriptor.get("version") or os.environ.get("GRYPE_VERSION") or None,
        "db_snapshot_id": os.environ.get("GRYPE_DB_SNAPSHOT_ID", ""),
        "image_scan_skipped": grype_skipped,
        "db": {
            "schema_version": grype_db_status.get("schemaVersion"),
            "built": grype_db_status.get("built"),
            "from": grype_db_status.get("from"),
            "valid": grype_db_status.get("valid"),
        } if grype_db_status else None,
        "error": grype_error,
    }
    if not grype_skipped:
        if grype_error or not isinstance(grype_report, dict):
            issues.append(f"invalid Grype image report: {grype_error or 'not an object'}")
        if grype_runtime["grype_version"] != os.environ.get("GRYPE_VERSION"):
            issues.append("Grype runtime version differs from configured version")
        if not grype_runtime["db_snapshot_id"]:
            issues.append("Grype database snapshot ID was not configured")
        if not grype_db_status.get("built") or not grype_db_status.get("schemaVersion"):
            issues.append("Grype vulnerability database metadata was not captured")

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_url = f"{server}/{repository}/actions/runs/{run_id}" if run_id and repository else ""
    if run_url and attempt:
        run_url += f"/attempts/{attempt}"

    record = {
        "schema_version": 6,
        "evidence_status": "complete" if not issues and run_url else "partial",
        "sample_type": "repository-baseline" if fixture_id == "baseline" else "patch-fixture",
        "fixture_id": fixture_id,
        "cache_mode": cache_mode,
        "benchmark_role": benchmark_role,
        "scan_execution_mode": execution_mode,
        "e4_evidence_status": e4_evidence_status,
        "e4_requested": run_e4_requested,
        "e4_raw_reports": e4_report_states,
        "run_id": run_id,
        "run_attempt": attempt,
        "run_url": run_url,
        "commit": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_stage_started_at": (timing or {}).get("scan_stage_started_at", ""),
        "scan_stage_ended_at": (timing or {}).get("scan_stage_ended_at", ""),
        "policy_configured": os.environ.get("CONTEST_POLICY", ""),
        "trivy_db_snapshot_id": os.environ.get("TRIVY_DB_SNAPSHOT_ID", ""),
        "tool_versions_configured": {
            tool: os.environ.get(variable, "")
            for tool, variable in TOOL_VERSION_ENV.items()
        },
        "raw_reports": raw_reports,
        "normalized_findings": {
            "count": len(findings),
            "by_tool": dict(sorted(by_tool.items())),
            "by_severity": dict(sorted(by_severity.items())),
            "items": [
                {
                    key: item.get(key)
                    for key in ("tool", "rule_id", "category", "severity", "file", "resource", "fingerprint")
                }
                for item in findings
            ],
        },
        "gate": gate_summary,
        "policy_runs": policy_runs,
        "skipped_scans": skipped_scans,
        "timing": timing,
        "trivy_runtime": trivy_runtime,
        "grype_runtime": grype_runtime,
        "issues": issues + ([] if run_url else ["no GitHub Actions run URL in environment"]),
        "interpretation": (
            "One patch observation only; aggregate independent runs before reporting recall. "
            "Negative controls and repeated timing comparisons are not inferred."
            if fixture_id != "baseline"
            else "One observed repository baseline run only; this is not patch-by-patch recall, "
                 "negative-control false-positive measurement, or a repeated timing study."
        ),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {record['evidence_status']} scan observation: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
