#!/usr/bin/env python3
"""Validate and enrich the live E4 files extracted from a report-image artifact."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from e4_image_remediation import build_markdown


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
RAW_FILES = {
    "trivy_before": "raw/e4/trivy-image-before.json",
    "trivy_after": "raw/e4/trivy-image-after.json",
    "sbom_before": "raw/e4/sbom-before.cdx.json",
    "sbom_after": "raw/e4/sbom-after.cdx.json",
    "runtime": "experiment/trivy-runtime-image.json",
    "image_timing": "timing/image.json",
    "e4_summary": "e4/e4_image_remediation.json",
    "trivy_runtime_before_before_scan": "raw/e4/trivy-runtime-before-before-scan.json",
    "trivy_runtime_before_after_scan": "raw/e4/trivy-runtime-before-after-scan.json",
    "trivy_runtime_after_before_scan": "raw/e4/trivy-runtime-after-before-scan.json",
    "trivy_runtime_after_after_scan": "raw/e4/trivy-runtime-after-after-scan.json",
}


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read valid JSON from {path}: {error}") from error


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def vulnerability_counts(document: dict) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for result in document.get("Results") or []:
        for finding in result.get("Vulnerabilities") or []:
            severity = str(finding.get("Severity") or "UNKNOWN").upper()
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def image_metadata(document: dict) -> dict:
    metadata = document.get("Metadata") or {}
    image_config = metadata.get("ImageConfig") or {}
    config = image_config.get("config") or {}
    python_version = next(
        (value.split("=", 1)[1] for value in config.get("Env") or []
         if isinstance(value, str) and value.startswith("PYTHON_VERSION=")),
        None,
    )
    return {
        "image_id": metadata.get("ImageID"),
        "image_config_digest": metadata.get("ImageID"),
        "manifest_digest_available": bool(metadata.get("RepoDigests")),
        "repo_tags": metadata.get("RepoTags") or [],
        "repo_digests": metadata.get("RepoDigests") or [],
        "os": metadata.get("OS") or {},
        "architecture": image_config.get("architecture"),
        "python_version": python_version,
    }


def vulnerability_db(runtime: dict) -> dict | None:
    if not isinstance(runtime, dict):
        return None
    databases = runtime.get("databases") or {}
    for name, value in databases.items():
        if "vulnerability" in name.casefold() and isinstance(value, dict):
            return value
    return None


def normalized_vulnerability_db(runtime: dict) -> dict | None:
    database = vulnerability_db(runtime)
    if not database or not database.get("version") or not database.get("updated_at"):
        return None
    return {
        key: database.get(key)
        for key in ("version", "updated_at", "next_update")
        if database.get(key) is not None
    }


def analyze(artifact_root: Path, gate_artifact_root: Path | None = None) -> dict:
    paths = {key: artifact_root / value for key, value in RAW_FILES.items()}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise ValueError("missing required E4 artifact files: " + ", ".join(missing))

    summary = load_json(paths["e4_summary"])
    if not isinstance(summary.get("live"), dict):
        raise ValueError("E4 summary does not contain live results")
    runtime = load_json(paths["runtime"])
    timing = load_json(paths["image_timing"])
    scan_runtime_records = {
        key: load_json(paths[key])
        for key in (
            "trivy_runtime_before_before_scan",
            "trivy_runtime_before_after_scan",
            "trivy_runtime_after_before_scan",
            "trivy_runtime_after_after_scan",
        )
    }
    if not timing.get("run_id") or not timing.get("run_url") or not timing.get("commit"):
        raise ValueError("image timing artifact is missing run ID, URL, or commit")

    configured_tools = {}
    if gate_artifact_root:
        observations = list(gate_artifact_root.rglob("observation.json"))
        if len(observations) != 1:
            raise ValueError(f"expected one gate observation, found {len(observations)}")
        observation = load_json(observations[0])
        if (str(observation.get("run_id")) != str(timing["run_id"])
                or observation.get("commit") != timing["commit"]):
            raise ValueError("report-image and report-gate artifacts belong to different run/commit")
        configured_tools = observation.get("tool_versions_configured") or {}

    scan_docs = {
        "before": load_json(paths["trivy_before"]),
        "after": load_json(paths["trivy_after"]),
    }
    sboms = {
        "before": load_json(paths["sbom_before"]),
        "after": load_json(paths["sbom_after"]),
    }
    live = summary["live"]
    for side in ("before", "after"):
        measured_counts = vulnerability_counts(scan_docs[side])
        measured_sbom = len(sboms[side].get("components") or [])
        if measured_counts != live[side].get("vulnerabilities"):
            raise ValueError(f"{side} Trivy severity totals differ from the summary")
        if measured_sbom != live[side].get("sbom_packages"):
            raise ValueError(f"{side} SBOM component count differs from the summary")
        image_context = dict(live[side].get("image") or {})
        image_context.update(image_metadata(scan_docs[side]))
        live[side]["image"] = image_context
        live[side]["vulnerabilities_total"] = sum(measured_counts.values())
        sbom_metadata = sboms[side].get("metadata") or {}
        live[side]["sbom"] = {
            "serial_number": sboms[side].get("serialNumber"),
            "timestamp": sbom_metadata.get("timestamp"),
            "component": sbom_metadata.get("component"),
            "components": measured_sbom,
        }

    before = live["before"]["image"]
    after = live["after"]["image"]
    db = vulnerability_db(runtime)
    same_python = bool(before["python_version"] and before["python_version"] == after["python_version"])
    same_os = bool(before["os"] and before["os"] == after["os"])
    same_arch = bool(before["architecture"] and before["architecture"] == after["architecture"])
    job_db_snapshot_recorded = bool(db and db.get("updated_at"))
    job_db_snapshot = normalized_vulnerability_db(runtime)
    scan_db_snapshots = {
        key.removeprefix("trivy_runtime_"): normalized_vulnerability_db(record)
        for key, record in scan_runtime_records.items()
    }
    scan_trivy_versions = {
        record.get("trivy_version") for record in scan_runtime_records.values()
        if isinstance(record, dict) and record.get("trivy_version")
    }
    snapshot_fingerprints = {
        json.dumps(snapshot, sort_keys=True)
        for snapshot in scan_db_snapshots.values()
        if snapshot is not None
    }
    per_scan_db_snapshot_verified = (
        len(scan_db_snapshots) == 4
        and all(snapshot is not None for snapshot in scan_db_snapshots.values())
        and len(snapshot_fingerprints) == 1
        and job_db_snapshot is not None
        and json.dumps(job_db_snapshot, sort_keys=True) in snapshot_fingerprints
    )
    same_trivy_version = (
        len(scan_trivy_versions) == 1
        and runtime.get("trivy_version") in scan_trivy_versions
    )
    confounds = []
    for label, left, right in (
        ("Python version", before["python_version"], after["python_version"]),
        ("OS release", before["os"], after["os"]),
        ("architecture", before["architecture"], after["architecture"]),
    ):
        if left != right:
            confounds.append({"dimension": label, "before": left, "after": right})

    comparable = all((same_python, same_os, same_arch, same_trivy_version, per_scan_db_snapshot_verified))
    live["comparability"] = {
        "same_application_build_context": True,
        "same_python_version": same_python,
        "same_os_release": same_os,
        "same_architecture": same_arch,
        "same_trivy_version": same_trivy_version,
        "shared_trivy_database_snapshot": per_scan_db_snapshot_verified,
        "job_level_trivy_snapshot_recorded": job_db_snapshot_recorded,
        "per_scan_trivy_snapshot_verified": per_scan_db_snapshot_verified,
        "confounds": confounds,
        "causal_attribution_allowed": comparable,
        "interpretation": (
            "All four raw per-scan records match the image-job Trivy DB snapshot and tool version; "
            "the before/after images also match Python, OS, and architecture. The aggregate delta "
            "is comparable for the Dockerfile/image change as a whole."
            if comparable else
            "Treat the before/after delta as descriptive because one or more runtime, platform, "
            "tool-version, or per-scan vulnerability-database comparisons could not be verified."
        ),
    }
    live["evidence_status"] = "comparable" if comparable else "limited"
    live["provenance"] = {
        "ci_run_id": str(timing["run_id"]),
        "ci_run_attempt": str(timing.get("run_attempt", "")),
        "ci_run_url": timing["run_url"],
        "commit": timing["commit"],
        "fixture_id": timing.get("fixture_id", "baseline"),
        "tool_versions": {
            "trivy": runtime.get("trivy_version"),
            "syft": configured_tools.get("syft") or (
                (summary.get("live", {}).get("provenance", {}).get("tool_versions") or {}).get("syft")
            ),
        },
        "trivy_vulnerability_database": db,
        "trivy_database_snapshots_per_scan": scan_db_snapshots,
        "trivy_database_snapshot_scope": (
            "four raw records verified: before/after each E4 image scan"
            if per_scan_db_snapshot_verified else
            "per-scan records are missing or do not match the image-job snapshot"
        ),
    }
    live["raw_artifact_sha256"] = {
        key: hash_file(path)
        for key, path in paths.items()
        if key not in {"e4_summary", "image_timing", "runtime"}
    }
    summary["evidence_status"] = live["evidence_status"]
    summary["causal_attribution_allowed"] = comparable
    summary["source_run_url"] = timing["run_url"]
    summary["source_commit"] = timing["commit"]
    summary["data_origin"] = "raw Trivy and Syft reports from the report-image GitHub Actions artifact"
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path, help="Extracted report-image artifact directory")
    parser.add_argument("--gate-artifact-dir", type=Path,
                        help="Optional extracted report-gate directory used to verify the same run and configured tool versions")
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-md", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.artifact_dir, args.gate_artifact_dir)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(build_markdown(result) + "\n", encoding="utf-8")
    print(f"E4 artifact analysis: {result['evidence_status']}")
    print(f"Causal attribution allowed: {result['causal_attribution_allowed']}")
    print(f"Run: {result['source_run_url']}")
    print(f"JSON: {args.out_json}")
    print(f"Markdown: {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
