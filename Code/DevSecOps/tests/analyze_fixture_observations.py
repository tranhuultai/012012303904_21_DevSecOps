#!/usr/bin/env python3
"""Aggregate manual workflow_dispatch fixture observations into E1 evidence.

Expected input is a directory containing downloaded Actions artifacts with
reports/experiment/observation.json. Each fixture must have one baseline from
the exact same commit; multiple commit-matched study slices can be aggregated.
"""

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


POLICIES = ("g0", "g1", "g2")


def load_ground_truth(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return {row["id"]: row for row in csv.DictReader(stream)}


def load_observations(input_dir):
    observations = []
    errors = []
    for path in sorted(input_dir.rglob("observation.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: {error}")
            continue
        if not isinstance(record, dict):
            errors.append(f"{path}: observation root is not an object")
            continue
        record["_source_path"] = str(path)
        observations.append(record)
    return observations, errors


def finding_identity(item):
    tool = str(item.get("tool") or "").lower()
    if tool == "grype":
        # Image layers and the order of package locations can change when
        # rebuilding an otherwise equivalent image. Match Grype findings
        # by CVE and package when available; older observations omit the
        # package field, so fall back to the CVE and ignore the unstable path.
        return ("grype", item.get("rule_id"), item.get("resource") or "")
    if tool == "checkov":
        # Checkov fingerprints include source line numbers. A harmless comment
        # can move a finding while leaving the rule and Terraform/K8s resource
        # unchanged, so compare those stable fields instead.
        file_path = str(item.get("file") or "").replace("\\", "/").strip("/").lower()
        return (
            "checkov",
            str(item.get("rule_id") or ""),
            str(item.get("resource") or ""),
            file_path,
        )
    fingerprint = item.get("fingerprint")
    return ("fingerprint", fingerprint) if fingerprint else None


def finding_fingerprints(observation):
    findings = observation.get("normalized_findings", {}).get("items", [])
    return {
        identity
        for item in findings
        if isinstance(item, dict)
        if (identity := finding_identity(item)) is not None
    }


VULNERABILITY_ID = re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+)\b", re.IGNORECASE)
SEVERITY_IN_MESSAGE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", re.IGNORECASE)


def path_matches(finding_path, expected_path):
    actual = str(finding_path or "").replace("\\", "/").strip("/").lower()
    expected = str(expected_path or "").replace("\\", "/").strip("/").lower()
    for prefix in ("code/devsecops/",):
        if expected.startswith(prefix):
            expected = expected[len(prefix):]
        if actual.startswith(prefix):
            actual = actual[len(prefix):]
    return bool(
        actual
        and expected
        and (
            actual == expected
            or actual.endswith("/" + expected)
            or expected.endswith("/" + actual)
        )
    )


def finding_matches_rule(finding, expected_rules):
    identity = " ".join((
        str(finding.get("rule_id") or ""),
        str(finding.get("resource") or ""),
    )).casefold()
    return any(rule and rule.casefold() in identity for rule in expected_rules)


def finding_matches_defect(finding, row):
    expected_tool = str(row.get("expected_tool") or "").lower()
    actual_tool = str(finding.get("tool") or "").lower()
    if actual_tool != expected_tool:
        return False
    # Trivy SCA locations refer to the installed distribution metadata inside
    # the scan environment, not the requirements manifest that introduced it.
    # For SCA, the exact CVE and scanner are the stable match; other categories
    # still require the expected source file.
    file_matches = (
        row.get("category") == "sca" and expected_tool == "trivy"
    ) or path_matches(finding.get("file"), row.get("file"))
    return file_matches and finding_matches_rule(finding, [row.get("rule_or_cve", "")])


def outcome_for_policy(observation, policy):
    for result in observation.get("policy_runs", []):
        if isinstance(result, dict) and result.get("policy") == policy:
            return result.get("decision")
    gate = observation.get("gate") or {}
    if gate.get("policy") == policy:
        return gate.get("decision")
    return None


def blockers_for_policy(observation, policy):
    for result in observation.get("policy_runs", []):
        if isinstance(result, dict) and result.get("policy") == policy:
            blockers = result.get("blockers")
            return blockers if isinstance(blockers, list) else None
    return None


def new_blockers_for_policy(observation, baseline, policy):
    current = blockers_for_policy(observation, policy)
    base = blockers_for_policy(baseline, policy)
    if current is None or base is None:
        return None
    def signature(item):
        message = str(item.get("message") or "")
        vulnerability = VULNERABILITY_ID.search(message)
        if vulnerability:
            severity = SEVERITY_IN_MESSAGE.search(message)
            return (
                str(item.get("rule_id") or ""),
                vulnerability.group(0).upper(),
                severity.group(1).upper() if severity else "",
            )
        return (
            str(item.get("rule_id") or ""),
            message,
            str(item.get("file") or ""),
        )
    baseline_signatures = {signature(item) for item in base if isinstance(item, dict)}
    return [
        item for item in current
        if isinstance(item, dict) and signature(item) not in baseline_signatures
    ]


def warnings_for_policy(observation, policy):
    for result in observation.get("policy_runs", []):
        if isinstance(result, dict) and result.get("policy") == policy:
            warnings = result.get("warnings")
            return warnings if isinstance(warnings, list) else None
    return None


def new_warnings_for_policy(observation, baseline, policy):
    current = warnings_for_policy(observation, policy)
    base = warnings_for_policy(baseline, policy)
    if current is None or base is None:
        return None

    def signatures(item):
        rule_id = str(item.get("rule_id") or "")
        affected = tuple(sorted(
            (
                str(finding.get("tool") or ""),
                str(finding.get("category") or ""),
                str(finding.get("title") or ""),
                str(finding.get("resource") or ""),
                str(finding.get("package") or ""),
                str(finding.get("installed_version") or ""),
            )
            for finding in item.get("affected_findings", [])
            if isinstance(finding, dict)
        ))
        control_ids = item.get("control_ids")
        if isinstance(control_ids, list) and control_ids:
            # Gate reports aggregate many controls into one warning. Compare
            # each control/source pair so fixing one control does not make the
            # changed aggregate look new, while a newly affected resource is
            # still visible when the same control already warned elsewhere.
            if affected:
                return {
                    (rule_id, "control-finding", str(control_id), identity)
                    for control_id in control_ids
                    for identity in affected
                }
            return {(rule_id, "control", str(control_id)) for control_id in control_ids}
        advisory_ids = item.get("advisory_ids")
        if isinstance(advisory_ids, list) and advisory_ids:
            if affected:
                return {
                    (rule_id, "advisory-finding", str(advisory_id), str(item.get("severity") or ""), identity)
                    for advisory_id in advisory_ids
                    for identity in affected
                }
            return {
                (rule_id, "advisory", str(advisory_id), str(item.get("severity") or ""))
                for advisory_id in advisory_ids
            }
        if affected:
            return {(rule_id, "finding", identity) for identity in affected}
        return {(rule_id, str(item.get("message") or ""), str(item.get("file") or ""))}

    baseline_signatures = {
        signature
        for item in base if isinstance(item, dict)
        for signature in signatures(item)
    }
    return [
        item for item in current
        if isinstance(item, dict) and signatures(item) - baseline_signatures
    ]


def blocker_matches_target(blocker, expected_rules):
    identity = " ".join((
        str(blocker.get("rule_id") or ""),
        str(blocker.get("message") or ""),
    )).casefold()
    # Conftest reports the evaluated gate_input.json as filename; the Rego
    # blocker message carries the finding rule, so match the unique target ID.
    return any(rule and rule.casefold() in identity for rule in expected_rules)


def policy_confusion_bucket(expected_action, has_new_blocker):
    """Classify incremental gate behavior against a fixture's declared action.

    The full policy decision can already be BLOCK on the common baseline. E2
    therefore compares newly introduced blockers with the ground-truth action.
    WARN and PASS both mean the fixture should not introduce a release block.
    """
    expected = str(expected_action or "").strip().upper()
    if expected not in {"PASS", "WARN", "BLOCK"}:
        return None
    blocked = bool(has_new_blocker)
    if expected == "BLOCK":
        return "TP" if blocked else "FN"
    return "FP" if blocked else "TN"


def comparable_trivy_runtime(observation, ignored_jobs=()):
    runtime = observation.get("trivy_runtime", {})
    ignored_jobs = set(ignored_jobs)
    return {
        job: value for job, value in runtime.items()
        if job not in ignored_jobs
    }


def comparable_grype_runtime(observation, ignore_image=False):
    if ignore_image:
        return None
    runtime = observation.get("grype_runtime")
    if not isinstance(runtime, dict):
        return None  # Legacy v3 observations did not record Grype DB provenance.
    if runtime.get("image_scan_skipped"):
        return None
    database = runtime.get("db")
    if not isinstance(database, dict):
        return None
    return {
        "grype_version": runtime.get("grype_version"),
        "db_snapshot_id": runtime.get("db_snapshot_id"),
        "schema_version": database.get("schema_version"),
        "built": database.get("built"),
        "from": database.get("from"),
        "valid": database.get("valid"),
    }


def ignored_runtime_jobs_for_pair(observation, baseline):
    """Ignore image Trivy metadata when either run intentionally skipped images."""
    image_scan_steps = {"image-build", "trivy-image", "syft-sbom", "grype-image"}
    for item in (observation, baseline):
        if set(item.get("skipped_scans", [])) & image_scan_steps:
            return {"image"}
    return set()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    project_dir = Path(__file__).resolve().parents[1]
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--ground-truth", default=project_dir / "ground_truth" / "ground_truth.csv", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    truth = load_ground_truth(args.ground_truth)
    observations, errors = load_observations(args.input_dir)
    incomplete = [item for item in observations if item.get("evidence_status") != "complete"]
    complete_fixture_ids = {
        item.get("fixture_id", "baseline")
        for item in observations
        if item.get("evidence_status") == "complete"
    }
    excluded_incomplete_observations = []
    for item in incomplete:
        fixture_id = item.get("fixture_id", "unknown")
        excluded_incomplete_observations.append({
            "fixture_id": fixture_id,
            "source_path": item.get("_source_path"),
            "issues": item.get("issues", []),
        })
        if fixture_id not in complete_fixture_ids:
            errors.append(
                f"no complete observation for {fixture_id}; incomplete attempt: "
                f"{item.get('_source_path')}"
            )
    observations = [item for item in observations if item.get("evidence_status") == "complete"]
    for observation in observations:
        missing_policy_reports = [
            policy for policy in POLICIES
            if outcome_for_policy(observation, policy) is None
            or blockers_for_policy(observation, policy) is None
            or warnings_for_policy(observation, policy) is None
        ]
        if missing_policy_reports:
            errors.append(
                f"missing policy/blocker/warning detail for {observation.get('fixture_id', 'baseline')}: "
                f"{', '.join(missing_policy_reports)}"
            )
    baseline_records = [item for item in observations if item.get("fixture_id", "baseline") == "baseline"]
    baseline_by_commit = {}
    for baseline_record in baseline_records:
        commit = baseline_record.get("commit")
        if not commit:
            errors.append(f"baseline observation has no commit: {baseline_record.get('_source_path')}")
            continue
        if commit in baseline_by_commit:
            errors.append(f"multiple baseline observations use commit {commit}")
            continue
        baseline_by_commit[commit] = baseline_record
    if not baseline_by_commit:
        errors.append("expected at least one complete baseline observation; found none")
    baseline = next(iter(baseline_by_commit.values()), None)
    baseline_commits = sorted(baseline_by_commit)
    base_commit = baseline_commits[0] if len(baseline_commits) == 1 else None

    def baseline_for(observation):
        return baseline_by_commit.get(observation.get("commit"))

    by_case = defaultdict(list)
    for observation in observations:
        case_id = observation.get("fixture_id", "baseline")
        if case_id == "baseline":
            continue
        by_case[case_id].append(observation)
        paired_baseline = baseline_for(observation)
        if not paired_baseline:
            errors.append(
                f"{case_id} uses commit {observation.get('commit')} with no same-commit baseline"
            )
            continue
        if observation.get("tool_versions_configured") != paired_baseline.get("tool_versions_configured"):
            errors.append(f"{case_id} tool versions differ from its same-commit baseline")
        if observation.get("trivy_db_snapshot_id") != paired_baseline.get("trivy_db_snapshot_id"):
            errors.append(f"{case_id} Trivy database snapshot key differs from its same-commit baseline")
        ignored_runtime_jobs = ignored_runtime_jobs_for_pair(observation, paired_baseline)
        if comparable_trivy_runtime(observation, ignored_runtime_jobs) != comparable_trivy_runtime(
            paired_baseline, ignored_runtime_jobs
        ):
            errors.append(f"{case_id} Trivy vulnerability database metadata differs from its same-commit baseline")
        if not ignored_runtime_jobs:
            grype_runtime = comparable_grype_runtime(observation)
            baseline_grype_runtime = comparable_grype_runtime(paired_baseline)
            if grype_runtime != baseline_grype_runtime and (grype_runtime or baseline_grype_runtime):
                errors.append(f"{case_id} Grype vulnerability database metadata differs from its same-commit baseline")

    defects = {case_id: row for case_id, row in truth.items() if row.get("type") == "defect"}
    cleans = {case_id: row for case_id, row in truth.items() if row.get("type") == "clean"}
    controls = {case_id: row for case_id, row in truth.items() if row.get("type") == "control"}
    expected_cases = set(defects) | set(cleans)
    supplied_cases = set(by_case)
    unknown_cases = supplied_cases - expected_cases - set(controls)
    if unknown_cases:
        errors.append(f"observations contain unknown fixture IDs: {', '.join(sorted(unknown_cases))}")

    case_results = []
    scanner_counts = Counter()
    scanner_attempts = Counter()
    policy_counts = {policy: Counter() for policy in POLICIES}
    clean_policy_counts = {policy: Counter() for policy in POLICIES}
    policy_attempts = Counter()
    clean_new_finding_cases = 0
    control_scanner_counts = Counter()
    control_policy_counts = {policy: Counter() for policy in POLICIES}

    for case_id in sorted(supplied_cases & expected_cases):
        row = truth[case_id]
        records = by_case[case_id]
        for observation in records:
            paired_baseline = baseline_for(observation)
            paired_fingerprints = finding_fingerprints(paired_baseline) if paired_baseline else set()
            new_items = [
                item for item in observation.get("normalized_findings", {}).get("items", [])
                if isinstance(item, dict) and finding_identity(item) not in paired_fingerprints
            ]
            if row.get("type") == "defect":
                detected = any(finding_matches_defect(item, row) for item in new_items)
                scanner_counts["detected"] += int(detected)
                scanner_counts["missed"] += int(not detected)
                scanner_attempts["defect"] += 1
            else:
                introduced = bool(new_items)
                clean_new_finding_cases += int(introduced)
                scanner_counts["clean_with_new_findings"] += int(introduced)
                scanner_counts["clean_without_new_findings"] += int(not introduced)
                scanner_attempts["clean"] += 1

            decisions = {}
            incremental_actions = {}
            expected_actions = {}
            target_specific_blocked = {}
            for policy in POLICIES:
                decision = outcome_for_policy(observation, policy)
                decisions[policy] = decision
                new_blockers = new_blockers_for_policy(observation, paired_baseline, policy) if paired_baseline else None
                new_warnings = new_warnings_for_policy(observation, paired_baseline, policy) if paired_baseline else None
                expected_action = str(row.get(f"expected_{policy}") or "").strip().upper()
                expected_actions[policy] = expected_action or None
                incremental_actions[policy] = (
                    "BLOCK" if new_blockers else "WARN" if new_warnings else "PASS"
                ) if new_blockers is not None and new_warnings is not None else None
                if (
                    decision not in {"PASS", "WARN", "BLOCK"}
                    or new_blockers is None
                    or new_warnings is None
                ):
                    continue
                bucket = policy_confusion_bucket(expected_action, bool(new_blockers))
                if bucket is None:
                    errors.append(f"{case_id} missing valid expected_{policy} action")
                    continue
                values = policy_counts[policy]
                policy_attempts[policy] += 1
                values[bucket] += 1
                if row.get("type") == "clean":
                    clean_policy_counts[policy][bucket] += 1
                values[f"expected_{expected_action.lower()}"] += 1
                values["action_aligned"] += int(incremental_actions[policy] == expected_action)
                target_match = any(
                    blocker_matches_target(item, [row.get("rule_or_cve", "")])
                    for item in new_blockers
                )
                target_specific_blocked[policy] = target_match
                values["target_specific_blocked"] += int(target_match)

            case_results.append({
                "fixture_id": case_id,
                "sample_type": row.get("type"),
                "run_url": observation.get("run_url"),
                "commit": observation.get("commit"),
                "evidence_status": observation.get("evidence_status"),
                "skipped_scans": observation.get("skipped_scans", []),
                "scanner_detected_expected_tool": detected if row.get("type") == "defect" else None,
                "new_findings_count": len(new_items),
                "policy_decisions": decisions,
                "expected_policy_actions": expected_actions,
                "incremental_policy_actions": incremental_actions,
                "target_specific_blocked": target_specific_blocked,
            })

    for case_id in sorted(supplied_cases & set(controls)):
        row = controls[case_id]
        for observation in by_case[case_id]:
            paired_baseline = baseline_for(observation)
            paired_fingerprints = finding_fingerprints(paired_baseline) if paired_baseline else set()
            new_items = [
                item for item in observation.get("normalized_findings", {}).get("items", [])
                if isinstance(item, dict) and finding_identity(item) not in paired_fingerprints
            ]
            expected_tool = row.get("expected_tool", "").lower()
            related_defects = [
                value.strip()
                for value in str(row.get("control_for", "") or "").split(";")
                if value.strip()
            ]
            expected_rules = [
                truth[defect_id].get("rule_or_cve", "")
                for defect_id in related_defects
                if defect_id in truth
            ]
            detected = any(
                str(item.get("tool", "")).lower() == expected_tool
                and (
                    row.get("category") == "sca" and expected_tool == "trivy"
                    or path_matches(item.get("file"), row.get("file"))
                )
                and finding_matches_rule(item, expected_rules)
                for item in new_items
            )
            control_scanner_counts["attempts"] += 1
            control_scanner_counts["false_positive_findings"] += int(detected)
            control_scanner_counts["no_expected_finding"] += int(not detected)

            decisions = {}
            incremental_actions = {}
            for policy in POLICIES:
                decision = outcome_for_policy(observation, policy)
                decisions[policy] = decision
                new_blockers = new_blockers_for_policy(observation, paired_baseline, policy) if paired_baseline else None
                new_warnings = new_warnings_for_policy(observation, paired_baseline, policy) if paired_baseline else None
                if decision in {"PASS", "WARN", "BLOCK"} and new_blockers is not None:
                    control_policy_counts[policy]["attempts"] += 1
                    control_policy_counts[policy]["blocked"] += int(bool(new_blockers))
                    control_policy_counts[policy]["not_blocked"] += int(not new_blockers)
                    incremental_actions[policy] = (
                        "BLOCK" if new_blockers else "WARN" if new_warnings else "PASS"
                    ) if new_warnings is not None else None
                else:
                    incremental_actions[policy] = None

            case_results.append({
                "fixture_id": case_id,
                "sample_type": "control",
                "run_url": observation.get("run_url"),
                "commit": observation.get("commit"),
                "evidence_status": observation.get("evidence_status"),
                "skipped_scans": observation.get("skipped_scans", []),
                "scanner_detected_expected_tool": detected,
                "new_findings_count": len(new_items),
                "policy_decisions": decisions,
                "expected_policy_actions": {policy: "PASS" for policy in POLICIES},
                "incremental_policy_actions": incremental_actions,
            })

    policy_metrics = {}
    for policy in POLICIES:
        values = policy_counts[policy]
        counts = {key: values.get(key, 0) for key in ("TP", "FN", "FP", "TN")}
        defects_measured = counts["TP"] + counts["FN"]
        clean_counts = clean_policy_counts[policy]
        clean_measured = clean_counts.get("FP", 0) + clean_counts.get("TN", 0)
        recall = counts["TP"] / defects_measured if defects_measured else None
        precision = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else None
        false_block = clean_counts.get("FP", 0) / clean_measured if clean_measured else None
        policy_metrics[policy] = {
            **counts,
            "expected_block_cases": values.get("expected_block", 0),
            "expected_warn_cases": values.get("expected_warn", 0),
            "expected_pass_cases": values.get("expected_pass", 0),
            "expected_nonblocking_defects_blocked": sum(
                1 for result in case_results
                if result.get("sample_type") == "defect"
                and result.get("expected_policy_actions", {}).get(policy) in {"PASS", "WARN"}
                and result.get("incremental_policy_actions", {}).get(policy) == "BLOCK"
            ),
            "action_aligned_cases": values.get("action_aligned", 0),
            "action_mismatched_cases": policy_attempts[policy] - values.get("action_aligned", 0),
            "target_specific_blocked_cases": values.get("target_specific_blocked", 0),
            "action_alignment_rate": round(
                values.get("action_aligned", 0) / policy_attempts[policy], 4
            ) if policy_attempts[policy] else None,
            "defects_measured": defects_measured,
            "clean_changes_measured": clean_measured,
            "recall_blocked_defects": round(recall, 4) if recall is not None else None,
            "precision_blocked_defects": round(precision, 4) if precision is not None else None,
            "false_block_rate_on_measured_clean": round(false_block, 4) if false_block is not None else None,
        }

    report = {
        "experiment": "E1/E2 actual scanner and gate observations",
        "evidence_status": "complete" if not errors and (expected_cases | set(controls)) <= supplied_cases else "partial",
        "baseline_run_url": baseline.get("run_url") if baseline else None,
        "baseline_commit": base_commit,
        "baseline_commits": baseline_commits,
        "baseline_runs": [
            {"commit": commit, "run_url": record.get("run_url")}
            for commit, record in sorted(baseline_by_commit.items())
        ],
        "fixture_cases_expected": len(expected_cases),
        "fixture_cases_measured": len(expected_cases & supplied_cases),
        "missing_cases": sorted(expected_cases - supplied_cases),
        "negative_controls_expected": len(controls),
        "negative_controls_measured": len(set(controls) & supplied_cases),
        "negative_controls_unmeasured": sorted(set(controls) - supplied_cases),
        "excluded_incomplete_observations": excluded_incomplete_observations,
        "negative_control_scanner_outcomes": {
            **control_scanner_counts,
            "expected_tool_false_positive_rate": (
                round(control_scanner_counts["false_positive_findings"] / control_scanner_counts["attempts"], 4)
                if control_scanner_counts["attempts"] else None
            ),
        },
        "negative_control_policy_outcomes": {
            policy: {
                **values,
                "false_block_rate": round(values["blocked"] / values["attempts"], 4)
                if values["attempts"] else None,
            }
            for policy, values in control_policy_counts.items()
        },
        "scanner_outcomes": {
            **scanner_counts,
            "defect_attempts": scanner_attempts["defect"],
            "clean_attempts": scanner_attempts["clean"],
            "clean_cases_with_new_findings": clean_new_finding_cases,
        },
        "policy_metrics": policy_metrics,
        "cases": case_results,
        "errors": errors,
        "limitations": [
            "Scanner detection means a new normalized finding matching expected tool and rule/CVE relative to a baseline observation for the exact same commit; file matching is required except for Trivy SCA, whose paths refer to installed distribution metadata rather than the requirements manifest.",
            "Grype image findings are baseline-matched by CVE and package when available; legacy observations without package identity fall back to CVE because image-layer paths are unstable across rebuilds.",
            "Schema v6 observations include a pinned Grype DB snapshot ID; Grype DB schema, build timestamp, source URL, snapshot ID, and runtime version are compared with the same-commit baseline. Intentional image-scan skips are excluded.",
            "Clean-change false-block counts cover Cxx fixtures; Nxx scanner false positives and gate false blocks are reported separately.",
            "Gate outcomes use blocker details added relative to a baseline observation for the exact same commit; pre-existing baseline blockers are not attributed to a fixture.",
            "TP/FN/FP/TN compare expected BLOCK versus whether the fixture introduced a new blocker. Exact action alignment separately compares expected PASS/WARN/BLOCK with new blocker and warning details relative to baseline.",
            "Target-specific blocker counts are diagnostic only; a newly introduced blocker for a different finding can still correctly block a fixture when the seeded change introduced additional high-risk findings.",
            "Repeat runs are counted as attempts; report the number of runs and avoid treating repeated copies of a case as independent defects.",
            "Each fixture is paired only with a baseline on its exact commit. Trivy CLI and database metadata must also match within each pair; findings from runs with different database metadata are not pooled.",
        ],
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "e1_e2_live_observations.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    defect_detection_text = (
        f"{scanner_counts['detected']}/{scanner_attempts['defect']}"
        if scanner_attempts["defect"] else "chưa có dữ liệu"
    )
    clean_finding_text = (
        f"{clean_new_finding_cases}/{scanner_attempts['clean']}"
        if scanner_attempts["clean"] else "chưa có dữ liệu"
    )
    control_finding_text = (
        f"{control_scanner_counts['false_positive_findings']}/{control_scanner_counts['attempts']}"
        if control_scanner_counts["attempts"] else "chưa có dữ liệu"
    )
    markdown = [
        "# E1/E2 – Kết quả từ quan sát CI theo fixture",
        "",
        f"- Trạng thái dữ liệu: **{report['evidence_status']}**",
        f"- Commit baseline theo cặp: {', '.join(f'`{commit}`' for commit in baseline_commits) or 'chưa có'}",
        f"- Fixture D/C đã đo: {report['fixture_cases_measured']}/{report['fixture_cases_expected']}",
        f"- Negative controls đã đo: {report['negative_controls_measured']}/{report['negative_controls_expected']}",
        "",
        "## E1 – Finding mới từ scanner kỳ vọng",
        "",
        f"- Finding mới đúng tool/rule/file: {defect_detection_text} lần chạy lỗi gieo cài.",
        f"- C changes có finding mới: {clean_finding_text} lần chạy clean.",
        "",
        "## E2 – Quyết định gate theo policy",
        "",
        "TP/FN/FP/TN xét gate có thêm blocker so với baseline hay không; `Block trúng rule đích` yêu cầu blocker khớp CVE/rule gieo cài. Nếu hai số khác nhau, gate đã chặn nhưng do blocker khác.",
        "",
        "| Policy | TP | FN | FP | TN | Block recall | Block trúng rule đích | Đúng hành động | False-block clean |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for policy in POLICIES:
        metric = policy_metrics[policy]
        recall = metric["recall_blocked_defects"]
        false_block = metric["false_block_rate_on_measured_clean"]
        aligned = metric["action_alignment_rate"]
        recall_text = (
            f"{recall:.2%}"
            if recall is not None
            else "không áp dụng (G0 không có mẫu kỳ vọng BLOCK)"
            if policy == "g0"
            else "chưa đủ dữ liệu"
        )
        aligned_text = f"{aligned:.2%}" if aligned is not None else "chưa đủ dữ liệu"
        false_block_text = (
            f"{false_block:.2%}" if false_block is not None else "chưa đủ dữ liệu"
        )
        target_specific_text = (
            f"{metric['target_specific_blocked_cases']}/{metric['expected_block_cases']}"
            if metric["expected_block_cases"] else "—"
        )
        markdown.append(
            f"| {policy.upper()} | {metric['TP']} | {metric['FN']} | "
            f"{metric['FP']} | {metric['TN']} | {recall_text} | {target_specific_text} | "
            f"{aligned_text} | {false_block_text} |"
        )
    markdown.extend([
        "",
        "## N – Negative controls",
        "",
        f"- Finding mới đúng rule/CVE đích từ scanner kỳ vọng: {control_finding_text} lần chạy control.",
        "- Tỷ lệ trên là false positive của scanner trên N controls; nó không gộp với false-block của gate trên C changes.",
        "",
        "| Policy | Control bị BLOCK | Control không BLOCK | False-block trên N |",
        "|---|---:|---:|---:|",
    ])
    for policy in POLICIES:
        values = control_policy_counts[policy]
        rate = values["blocked"] / values["attempts"] if values["attempts"] else None
        rate_text = f"{rate:.2%}" if rate is not None else "chưa đủ dữ liệu"
        markdown.append(
            f"| {policy.upper()} | {values['blocked']} | {values['not_blocked']} | {rate_text} |"
        )
    markdown.extend([
        "",
        "## Giới hạn và mẫu còn thiếu",
        "",
        "- Các mẫu N chưa có kết quả thì không được suy ra là true negative.",
        "- Mỗi fixture chỉ được so với baseline cùng commit; nếu có nhiều commit thì mỗi commit cần baseline riêng và cùng phiên bản công cụ.",
        "- Xem JSON cạnh file này để truy vết run URL, finding, policy, report hash và fixture.",
        "",
        f"Thiếu fixture: {', '.join(report['missing_cases']) if report['missing_cases'] else 'không'}.",
        f"Thiếu negative control: {', '.join(report['negative_controls_unmeasured']) if report['negative_controls_unmeasured'] else 'không'}.",
    ])
    (args.out_dir / "e1_e2_live_observations.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    print(f"Wrote {report['evidence_status']} result: {args.out_dir / 'e1_e2_live_observations.json'}")
    print(f"Measured {report['fixture_cases_measured']}/{report['fixture_cases_expected']} D/C fixtures; "
          f"negative controls {report['negative_controls_measured']}/{report['negative_controls_expected']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
