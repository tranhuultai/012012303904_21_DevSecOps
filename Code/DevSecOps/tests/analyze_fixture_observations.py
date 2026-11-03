#!/usr/bin/env python3
"""Aggregate manual workflow_dispatch fixture observations into E1 evidence.

Expected input is a directory containing downloaded Actions artifacts with
reports/experiment/observation.json from one baseline and Dxx/Cxx runs.
"""

import argparse
import csv
import json
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


def finding_fingerprints(observation):
    findings = observation.get("normalized_findings", {}).get("items", [])
    return {
        item.get("fingerprint")
        for item in findings
        if isinstance(item, dict) and item.get("fingerprint")
    }


def path_matches(finding_path, expected_path):
    actual = str(finding_path or "").replace("\\", "/").strip("/").lower()
    expected = str(expected_path or "").replace("\\", "/").strip("/").lower()
    for prefix in ("code/devsecops/",):
        if expected.startswith(prefix):
            expected = expected[len(prefix):]
        if actual.startswith(prefix):
            actual = actual[len(prefix):]
    return bool(actual and expected and (actual == expected or actual.endswith("/" + expected)))


def finding_matches_rule(finding, expected_rules):
    identity = " ".join((
        str(finding.get("rule_id") or ""),
        str(finding.get("resource") or ""),
    )).casefold()
    return any(rule and rule.casefold() in identity for rule in expected_rules)


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
        return (
            str(item.get("rule_id") or ""),
            str(item.get("message") or ""),
            str(item.get("file") or ""),
        )
    baseline_signatures = {signature(item) for item in base if isinstance(item, dict)}
    return [
        item for item in current
        if isinstance(item, dict) and signature(item) not in baseline_signatures
    ]


def blocker_matches_target(blocker, expected_rules):
    identity = " ".join((
        str(blocker.get("rule_id") or ""),
        str(blocker.get("message") or ""),
    )).casefold()
    # Conftest reports the evaluated gate_input.json as filename; the Rego
    # blocker message carries the finding rule, so match the unique target ID.
    return any(rule and rule.casefold() in identity for rule in expected_rules)


def comparable_trivy_runtime(observation, ignored_jobs=()):
    runtime = observation.get("trivy_runtime", {})
    ignored_jobs = set(ignored_jobs)
    return {
        job: value for job, value in runtime.items()
        if job not in ignored_jobs
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
    for item in incomplete:
        errors.append(
            f"excluding incomplete observation for {item.get('fixture_id', 'unknown')}: "
            f"{item.get('_source_path')}"
        )
    observations = [item for item in observations if item.get("evidence_status") == "complete"]
    for observation in observations:
        missing_policy_reports = [
            policy for policy in POLICIES
            if outcome_for_policy(observation, policy) is None
            or blockers_for_policy(observation, policy) is None
        ]
        if missing_policy_reports:
            errors.append(
                f"missing policy/blocker detail for {observation.get('fixture_id', 'baseline')}: "
                f"{', '.join(missing_policy_reports)}"
            )
    baseline_records = [item for item in observations if item.get("fixture_id", "baseline") == "baseline"]
    if len(baseline_records) != 1:
        errors.append(f"expected exactly one baseline observation; found {len(baseline_records)}")
        baseline = baseline_records[0] if baseline_records else None
    else:
        baseline = baseline_records[0]

    if baseline:
        base_commit = baseline.get("commit")
        base_versions = baseline.get("tool_versions_configured")
        base_fingerprints = finding_fingerprints(baseline)
    else:
        base_commit = None
        base_versions = None
        base_fingerprints = set()

    by_case = defaultdict(list)
    for observation in observations:
        case_id = observation.get("fixture_id", "baseline")
        if case_id == "baseline":
            continue
        by_case[case_id].append(observation)
        if baseline and observation.get("commit") != base_commit:
            errors.append(f"{case_id} uses commit {observation.get('commit')}, baseline uses {base_commit}")
        if baseline and observation.get("tool_versions_configured") != base_versions:
            errors.append(f"{case_id} tool versions differ from baseline")
        if baseline:
            ignored_runtime_jobs = ignored_runtime_jobs_for_pair(observation, baseline)
            if comparable_trivy_runtime(observation, ignored_runtime_jobs) != comparable_trivy_runtime(
                baseline, ignored_runtime_jobs
            ):
                errors.append(f"{case_id} Trivy vulnerability database metadata differs from baseline")

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
    policy_attempts = Counter()
    clean_new_finding_cases = 0
    control_scanner_counts = Counter()
    control_policy_counts = {policy: Counter() for policy in POLICIES}

    for case_id in sorted(supplied_cases & expected_cases):
        row = truth[case_id]
        records = by_case[case_id]
        for observation in records:
            new_items = [
                item for item in observation.get("normalized_findings", {}).get("items", [])
                if isinstance(item, dict) and item.get("fingerprint") not in base_fingerprints
            ]
            if row.get("type") == "defect":
                expected_tool = row.get("expected_tool", "").lower()
                detected = any(
                    str(item.get("tool", "")).lower() == expected_tool
                    and path_matches(item.get("file"), row.get("file"))
                    and finding_matches_rule(item, [row.get("rule_or_cve", "")])
                    for item in new_items
                )
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
            for policy in POLICIES:
                decision = outcome_for_policy(observation, policy)
                decisions[policy] = decision
                new_blockers = new_blockers_for_policy(observation, baseline, policy) if baseline else None
                if decision not in {"PASS", "WARN", "BLOCK"} or new_blockers is None:
                    continue
                policy_attempts[policy] += 1
                expected_block = any(
                    blocker_matches_target(item, [row.get("rule_or_cve", "")])
                    for item in new_blockers
                )
                if row.get("type") == "defect":
                    policy_counts[policy]["TP" if expected_block else "FN"] += 1
                elif row.get("type") == "clean":
                    policy_counts[policy]["FP" if new_blockers else "TN"] += 1

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
            })

    for case_id in sorted(supplied_cases & set(controls)):
        row = controls[case_id]
        for observation in by_case[case_id]:
            new_items = [
                item for item in observation.get("normalized_findings", {}).get("items", [])
                if isinstance(item, dict) and item.get("fingerprint") not in base_fingerprints
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
                and path_matches(item.get("file"), row.get("file"))
                and finding_matches_rule(item, expected_rules)
                for item in new_items
            )
            control_scanner_counts["attempts"] += 1
            control_scanner_counts["false_positive_findings"] += int(detected)
            control_scanner_counts["no_expected_finding"] += int(not detected)

            decisions = {}
            for policy in POLICIES:
                decision = outcome_for_policy(observation, policy)
                decisions[policy] = decision
                new_blockers = new_blockers_for_policy(observation, baseline, policy) if baseline else None
                if decision in {"PASS", "WARN", "BLOCK"} and new_blockers is not None:
                    control_policy_counts[policy]["attempts"] += 1
                    control_policy_counts[policy]["blocked"] += int(bool(new_blockers))
                    control_policy_counts[policy]["not_blocked"] += int(not new_blockers)

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
            })

    policy_metrics = {}
    for policy in POLICIES:
        values = policy_counts[policy]
        defects_measured = values["TP"] + values["FN"]
        clean_measured = values["FP"] + values["TN"]
        recall = values["TP"] / defects_measured if defects_measured else None
        precision = values["TP"] / (values["TP"] + values["FP"]) if values["TP"] + values["FP"] else None
        false_block = values["FP"] / clean_measured if clean_measured else None
        policy_metrics[policy] = {
            **values,
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
        "fixture_cases_expected": len(expected_cases),
        "fixture_cases_measured": len(expected_cases & supplied_cases),
        "missing_cases": sorted(expected_cases - supplied_cases),
        "negative_controls_expected": len(controls),
        "negative_controls_measured": len(set(controls) & supplied_cases),
        "negative_controls_unmeasured": sorted(set(controls) - supplied_cases),
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
            "Scanner detection means a new normalized finding matching expected tool, rule/CVE, and file relative to the same-commit baseline.",
            "Clean-change false-block counts cover Cxx fixtures; Nxx scanner false positives and gate false blocks are reported separately.",
            "Gate outcomes use blocker details added relative to the same-commit baseline; pre-existing baseline blockers are not attributed to a fixture.",
            "Repeat runs are counted as attempts; report the number of runs and avoid treating repeated copies of a case as independent defects.",
            "Trivy CLI and database metadata must match the baseline; findings from runs with different database metadata are not pooled.",
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
        f"- Commit baseline: `{base_commit or 'chưa có'}`",
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
        "| Policy | TP | FN | FP | TN | Recall chặn lỗi | False-block trên clean |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for policy in POLICIES:
        metric = policy_metrics[policy]
        recall = metric["recall_blocked_defects"]
        false_block = metric["false_block_rate_on_measured_clean"]
        recall_text = f"{recall:.2%}" if recall is not None else "chưa đủ dữ liệu"
        false_block_text = (
            f"{false_block:.2%}" if false_block is not None else "chưa đủ dữ liệu"
        )
        markdown.append(
            f"| {policy.upper()} | {metric['TP']} | {metric['FN']} | "
            f"{metric['FP']} | {metric['TN']} | {recall_text} | {false_block_text} |"
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
        "- Chỉ gộp các run có cùng commit baseline và cùng phiên bản công cụ.",
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
