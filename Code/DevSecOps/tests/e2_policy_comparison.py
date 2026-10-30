#!/usr/bin/env python3
"""
E2 – So sánh chính sách G0, G1 và G2.

RQ3: Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?

Chạy E1 cho cả ba chính sách rồi so sánh:
    - Recall, Precision, F1, False-block-rate
    - Số lỗi bỏ sót theo tầng nghiêm trọng
    - Bảng so sánh tóm tắt

Đầu vào:
    --ground-truth   ground_truth/ground_truth.csv
    --findings       results/raw/findings.csv
    --out-dir        results/metrics/
"""

import argparse
import json
import sys
from pathlib import Path

# Fix Windows console UTF-8 printing safely
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Reuse E1 functions
sys.path.insert(0, str(Path(__file__).parent))
from e1_detection_effectiveness import load_ground_truth, load_findings, compute_metrics


POLICIES = ["g0", "g1", "g2"]

# Policy descriptions for the report
POLICY_DESC = {
    "g0": "Baseline – không chặn gì (đo nhiễu nền)",
    "g1": "Chặn tất cả MEDIUM+ (không xét bản vá, KEV, ngoại lệ)",
    "g2": "Chặn thông minh (KEV, bản vá, khóa kiểm soát tác động cao)",
}


def build_comparison_table(all_metrics: list[dict]) -> str:
    """Build a Markdown table comparing policies."""
    header = "| Policy | Recall | Precision | F1 | False-block | TP | FN | FP |"
    sep    = "|--------|--------|-----------|-----|-------------|-----|-----|-----|"
    rows = [header, sep]
    for m in all_metrics:
        rows.append(
            f"| {m['policy'].upper()} "
            f"| {m['recall']:.2%} "
            f"| {m['precision']:.2%} "
            f"| {m['f1']:.4f} "
            f"| {m['false_block_rate']:.2%} "
            f"| {m['TP']} "
            f"| {m['FN']} "
            f"| {m['FP']} |"
        )
    return "\n".join(rows)


def find_best_policy(all_metrics: list[dict]) -> str:
    """
    Recommend the policy with best F1 that has 0 false blocks.
    Falls back to lowest false_block_rate if all have false blocks.
    """
    zero_fb = [m for m in all_metrics if m["false_block_rate"] == 0]
    if zero_fb:
        return max(zero_fb, key=lambda m: m["f1"])["policy"]
    return min(all_metrics, key=lambda m: m["false_block_rate"])["policy"]


def main():
    parser = argparse.ArgumentParser(description="E2: Policy comparison G0 vs G1 vs G2")
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
        "--out-dir",
        default=str(project_dir / "tests" / "results" / "metrics"),
        help="Directory to write comparison JSON and Markdown",
    )
    args = parser.parse_args()

    gt_path = Path(args.ground_truth)
    if not gt_path.exists():
        print(f"ERROR: ground_truth file not found: {gt_path}", file=sys.stderr)
        return 1

    defects, cleans = load_ground_truth(gt_path)
    findings_by_change = load_findings(Path(args.findings))

    all_metrics = []
    for policy in POLICIES:
        m = compute_metrics(defects, cleans, findings_by_change, policy)
        all_metrics.append(m)

    # Print comparison table
    print("=" * 70)
    print("E2 – So sánh chính sách G0 / G1 / G2")
    print("=" * 70)
    print()
    for m in all_metrics:
        desc = POLICY_DESC.get(m["policy"], "")
        print(f"  {m['policy'].upper()}: {desc}")
    print()
    print(build_comparison_table(all_metrics))
    print()

    best = find_best_policy(all_metrics)
    print(f"Khuyến nghị: {best.upper()} – cân bằng tốt nhất giữa recall và false-block-rate")
    print()

    # Missed defect breakdown
    print("Lỗi bỏ sót theo chính sách:")
    for m in all_metrics:
        missed = m["missed_defects"]
        print(f"  {m['policy'].upper()}: {len(missed)} – {', '.join(missed) if missed else '(không có)'}")

    # Save outputs
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    comparison = {
        "experiment": "E2",
        "question": "RQ3",
        "policies": all_metrics,
        "recommended_policy": best,
    }
    json_out = out_dir / "e2_policy_comparison.json"
    json_out.write_text(json.dumps(comparison, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Markdown
    md_lines = [
        "# E2 – So sánh chính sách G0 / G1 / G2",
        "",
        "> **RQ3**: Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?",
        "",
        "## Bảng so sánh",
        "",
        build_comparison_table(all_metrics),
        "",
        "## Kết luận",
        "",
        f"Chính sách được khuyến nghị: **{best.upper()}**",
        "",
        f"_{POLICY_DESC.get(best, '')}_",
        "",
        "## Lỗi bỏ sót theo chính sách",
        "",
    ]
    for m in all_metrics:
        missed = m["missed_defects"]
        md_lines.append(
            f"- **{m['policy'].upper()}**: {len(missed)} lỗi bỏ sót"
            + (f" ({', '.join(missed)})" if missed else "")
        )

    md_out = out_dir / "e2_policy_comparison.md"
    md_out.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"\nKết quả lưu tại: {json_out}")
    print(f"Báo cáo Markdown: {md_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

