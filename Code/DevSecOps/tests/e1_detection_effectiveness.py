#!/usr/bin/env python3
"""
E1 – Đánh giá khả năng phát hiện lỗi của pipeline DevSecOps.

RQ1: Mức độ hiệu quả và tỷ lệ chặn nhầm của chính sách an ninh mặc định là bao nhiêu?
RQ2: Chính sách mặc định tạo ra bao nhiêu cảnh báo và kéo dài thời gian chạy pipeline ra sao?

Metric:
    - Recall     = TP / (TP + FN)          bắt được bao nhiêu lỗi thật
    - Precision  = TP / (TP + FP)          báo đúng bao nhiêu
    - F1         = 2 * P * R / (P + R)
    - False block rate = FP_clean / total_clean  (thay đổi sạch bị chặn)

Đầu vào:
    --ground-truth   ground_truth/ground_truth.csv  (cột: id, type, category, file, rule_or_cve, ...)
    --findings       results/raw/findings.csv        (cột: change_id, tool, rule_id, severity)
    --decisions      results/raw/decisions.csv       (kết quả policy đã ghi)
    --policy         g0 | g1 | g2
    --out-dir        results/metrics/
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# Fix Windows console UTF-8 printing safely
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

POLICY_BLOCK_SEVERITY = {
    "g0": set(),
    "g1": {"CRITICAL", "HIGH", "MEDIUM"},
    "g2": {"CRITICAL", "HIGH"},  # simplified for E1 analysis
}


def load_ground_truth(path: Path) -> tuple[dict, set]:
    """Load ground_truth.csv into two sets: defects and cleans."""
    defects = {}   # id -> row
    cleans = set()
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["type"] == "defect":
                defects[row["id"]] = row
            elif row["type"] == "clean":
                cleans.add(row["id"])
    return defects, cleans


def load_ground_truth_all(path: Path) -> tuple[dict, set, dict]:
    """Load ground_truth.csv into defects, cleans, and controls."""
    defects = {}
    cleans = set()
    controls = {}
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["type"] == "defect":
                defects[row["id"]] = row
            elif row["type"] == "clean":
                cleans.add(row["id"])
            elif row["type"] == "control":
                controls[row["id"]] = row
    return defects, cleans, controls


def load_findings(path: Path) -> dict:
    """Load findings CSV from pipeline run. Returns {change_id: [findings]}."""
    findings_by_change = defaultdict(list)
    if not path.exists():
        return findings_by_change
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            findings_by_change[row["change_id"]].append(row)
    return findings_by_change


def load_decisions(path: Path) -> dict:
    """Load recorded gate decisions as {policy: {change_id: decision}}."""
    if not path.exists():
        raise FileNotFoundError(f"Gate decisions not found: {path}")
    decisions = defaultdict(dict)
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            policy = row.get("policy", "").strip().lower()
            change_id = row.get("change_id", "").strip()
            decision = row.get("decision", "").strip().upper()
            if policy not in {"g0", "g1", "g2"} or not change_id:
                raise ValueError(f"Invalid decision row: {row}")
            if decision not in {"PASS", "WARN", "BLOCK"}:
                raise ValueError(f"Invalid decision value in row: {row}")
            if change_id in decisions[policy]:
                raise ValueError(f"Duplicate decision for {policy}/{change_id}")
            decisions[policy][change_id] = decision
    return decisions


def simulate_gate_decision(findings: list, policy: str) -> str:
    """Simulate gate decision based on policy and findings severity."""
    block_severities = POLICY_BLOCK_SEVERITY.get(policy, set())
    for f in findings:
        if f.get("severity", "").upper() in block_severities:
            return "BLOCK"
    if findings:
        return "WARN"
    return "PASS"


def compute_metrics(
    defects: dict,
    cleans: set,
    findings_by_change: dict,
    policy: str,
    decisions_by_policy: dict | None = None,
) -> dict:
    """Compute recall, precision, false block rate."""
    tp = 0  # defect found (BLOCK)
    fn = 0  # defect missed (PASS/WARN)
    fp = 0  # clean blocked (BLOCK)
    tn = 0  # clean passed

    blocked_defects = []
    missed_defects = []
    false_blocks = []

    recorded = (decisions_by_policy or {}).get(policy)

    def decision_for(change_id):
        if recorded is not None:
            if change_id not in recorded:
                raise ValueError(
                    f"Missing recorded decision for {policy}/{change_id}"
                )
            return recorded[change_id]
        return simulate_gate_decision(
            findings_by_change.get(change_id, []), policy
        )

    for change_id, row in defects.items():
        decision = decision_for(change_id)
        if decision == "BLOCK":
            tp += 1
            blocked_defects.append(change_id)
        else:
            fn += 1
            missed_defects.append(change_id)

    for change_id in cleans:
        decision = decision_for(change_id)
        if decision == "BLOCK":
            fp += 1
            false_blocks.append(change_id)
        else:
            tn += 1

    total_defects = tp + fn
    total_cleans = fp + tn

    recall = tp / total_defects if total_defects > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    false_block_rate = fp / total_cleans if total_cleans > 0 else 0.0

    return {
        "policy": policy,
        "total_defects": total_defects,
        "total_cleans": total_cleans,
        "TP": tp,
        "FN": fn,
        "FP": fp,
        "TN": tn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "false_block_rate": round(false_block_rate, 4),
        "blocked_defects": blocked_defects,
        "missed_defects": missed_defects,
        "false_blocks": false_blocks,
        "decision_source": "decisions.csv" if recorded is not None else "severity simulation",
        "measurement_note": (
            "Recorded policy outcomes; this file does not establish scanner detection "
            "unless paired with raw scanner reports and CI run links."
            if recorded is not None else "Simulated from finding severities."
        ),
    }


def print_report(metrics: dict):
    """Print formatted E1 report to stdout."""
    print("=" * 60)
    print(f"E1 – Kết quả policy (Policy: {metrics['policy'].upper()})")
    print(f"Nguồn quyết định: {metrics['decision_source']}")
    print("=" * 60)
    print(f"Tổng lỗi gieo:      {metrics['total_defects']}")
    print(f"Tổng thay đổi sạch: {metrics['total_cleans']}")
    print()
    print(f"TP (chặn lỗi đúng): {metrics['TP']}")
    print(f"FN (bỏ sót lỗi):   {metrics['FN']}")
    print(f"FP (chặn nhầm):    {metrics['FP']}")
    print(f"TN (sạch qua đúng):{metrics['TN']}")
    print()
    print(f"Recall trên bộ mẫu: {metrics['recall']:.2%}")
    print(f"Precision:          {metrics['precision']:.2%}")
    print(f"F1:                 {metrics['f1']:.4f}")
    print(f"Tỷ lệ chặn nhầm:   {metrics['false_block_rate']:.2%}")
    if metrics["missed_defects"]:
        print(f"\nLỗi bỏ sót: {', '.join(metrics['missed_defects'])}")
    if metrics["false_blocks"]:
        print(f"Chặn nhầm: {', '.join(metrics['false_blocks'])}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="E1: Detection effectiveness analysis")
    project_dir = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--ground-truth",
        default=str(project_dir / "ground_truth" / "ground_truth.csv"),
        help="Path to ground_truth.csv",
    )
    parser.add_argument(
        "--findings",
        default=str(project_dir / "tests" / "results" / "raw" / "findings.csv"),
        help="Path to pipeline findings CSV",
    )
    parser.add_argument(
        "--decisions",
        default=str(project_dir / "tests" / "results" / "raw" / "decisions.csv"),
        help="Path to recorded per-policy gate decisions CSV",
    )
    parser.add_argument(
        "--policy",
        choices=["g0", "g1", "g2"],
        default="g1",
        help="Policy to evaluate",
    )
    parser.add_argument(
        "--out-dir",
        default=str(project_dir / "tests" / "results" / "metrics"),
        help="Directory to write metrics JSON",
    )
    args = parser.parse_args()

    gt_path = Path(args.ground_truth)
    if not gt_path.exists():
        print(f"ERROR: ground_truth file not found: {gt_path}", file=sys.stderr)
        return 1

    defects, cleans = load_ground_truth(gt_path)
    _, _, controls = load_ground_truth_all(gt_path)
    findings_by_change = load_findings(Path(args.findings))
    decisions_by_policy = load_decisions(Path(args.decisions))

    metrics = compute_metrics(
        defects, cleans, findings_by_change, args.policy, decisions_by_policy
    )
    metrics["negative_controls_total"] = len(controls)
    metrics["negative_controls_measured"] = 0
    metrics["measurement_note"] += (
        " Negative controls are not included: no scanner outcomes are recorded "
        "for N01-N08. False-block rate covers only the 10 clean changes in this fixture."
    )
    print_report(metrics)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"e1_{args.policy}_metrics.json"
    out_file.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nKết quả lưu tại: {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

