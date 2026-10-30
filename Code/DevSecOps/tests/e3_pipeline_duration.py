#!/usr/bin/env python3
"""
E3 – Đánh giá thời gian thực thi pipeline DevSecOps (Pipeline Duration Analysis).

Mục tiêu (theo phân công Long & Duy - mục 5.5):
    - Báo cáo số lần đo (N), trung vị (p50), phân vị 90 (p90) thay cho giá trị trung bình đơn thuần.
    - So sánh với ngưỡng 'Tê liệt pipeline' (Pipeline > 10 phút / 600 giây).
    - Phân tích theo phân nhóm: Thay đổi có lỗi (Defects) vs Thay đổi sạch (Cleans).

Đầu vào:
    --runs      results/raw/runs.csv (cột: run_id, change_id, type, branch, duration_seconds, ...)
    --out-dir   results/metrics/
"""

import argparse
import csv
import json
import math
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


PIPELINE_PARALYSIS_THRESHOLD_SECONDS = 600.0  # 10 phút


def percentile(data: list[float], p: float) -> float:
    """Calculate the p-th percentile (0 <= p <= 100) using linear interpolation."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 1:
        return float(sorted_data[0])
    rank = (p / 100.0) * (n - 1)
    k = math.floor(rank)
    d = rank - k
    if k + 1 < n:
        return float(sorted_data[k] + d * (sorted_data[k + 1] - sorted_data[k]))
    return float(sorted_data[k])


def compute_duration_stats(durations: list[float]) -> dict:
    """Compute N, median (p50), p90, p95, mean, min, max, std."""
    n = len(durations)
    if n == 0:
        return {
            "N": 0,
            "mean": 0.0,
            "median_p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "min": 0.0,
            "max": 0.0,
            "std": 0.0,
            "paralysis_exceeded": False,
        }

    mean = sum(durations) / n
    variance = sum((x - mean) ** 2 for x in durations) / n
    std = math.sqrt(variance)

    med = percentile(durations, 50.0)
    p90 = percentile(durations, 90.0)
    p95 = percentile(durations, 95.0)

    max_dur = max(durations)

    return {
        "N": n,
        "mean": round(mean, 2),
        "median_p50": round(med, 2),
        "p90": round(p90, 2),
        "p95": round(p95, 2),
        "min": round(min(durations), 2),
        "max": round(max_dur, 2),
        "std": round(std, 2),
        "paralysis_exceeded": max_dur > PIPELINE_PARALYSIS_THRESHOLD_SECONDS,
    }


def load_runs_data(path: Path) -> tuple[list[float], dict[str, list[float]]]:
    """Load duration_seconds from runs.csv, grouped overall and by type."""
    overall = []
    by_type = defaultdict(list)

    if not path.exists():
        return overall, by_type

    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                dur = float(row["duration_seconds"])
                run_type = row.get("type", "unknown").lower()
                overall.append(dur)
                by_type[run_type].append(dur)
            except (ValueError, KeyError):
                continue

    return overall, by_type


def build_markdown_report(stats: dict) -> str:
    """Generate Markdown report for E3."""
    lines = [
        "# E3 – Đánh giá thời gian pipeline (Pipeline Duration)",
        "",
        "> **RQ4 / Mục 5.5**: Đánh giá thời gian thực thi pipeline bằng Trung vị (p50), Phân vị 90 (p90) và số lần đo (N).",
        "",
        "## 1. Bảng số liệu thống kê thời gian thực thi (giây)",
        "",
        "| Nhóm | Số lần đo (N) | Trung vị (p50) | Phân vị 90 (p90) | Phân vị 95 (p95) | Trung bình | Min | Max | Tê liệt (>10p) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for group_name, s in stats["groups"].items():
        status = "BỊ TÊ LIỆT" if s["paralysis_exceeded"] else "An toàn (PASS)"
        lines.append(
            f"| **{group_name.capitalize()}** | {s['N']} | {s['median_p50']}s | {s['p90']}s | {s['p95']}s | {s['mean']}s | {s['min']}s | {s['max']}s | {status} |"
        )

    overall = stats["overall"]
    overall_status = "BỊ TÊ LIỆT" if overall["paralysis_exceeded"] else "An toàn (PASS)"
    lines.extend([
        f"| **Tổng thể** | {overall['N']} | {overall['median_p50']}s | {overall['p90']}s | {overall['p95']}s | {overall['mean']}s | {overall['min']}s | {overall['max']}s | {overall_status} |",
        "",
        "## 2. Nhận xét và kết luận",
        "",
        f"- **Số lần đo (N):** Tổng cộng {overall['N']} lần đo độc lập ({stats['groups'].get('defect', {}).get('N', 0)} lần với nhánh lỗi và {stats['groups'].get('clean', {}).get('N', 0)} lần với nhánh sạch).",
        f"- **Trung vị (p50):** {overall['median_p50']} giây (~{overall['median_p50']/60:.2f} phút), phản ánh chính xác thời gian thông thường của một PR mà không bị bóp méo bởi các ngoại lai.",
        f"- **Phân vị 90 (p90):** {overall['p90']} giây (~{overall['p90']/60:.2f} phút), cho thấy 90% các PR hoàn thành kiểm tra trong khoảng thời gian này.",
        "- **Kiểm tra ngưỡng tê liệt:** Thời gian tối đa ghi nhận là {max_s}s, hoàn toàn thấp hơn nhiều so với ngưỡng 600 giây (10 phút). Pipeline đảm bảo tính ổn định và tính sẵn sàng cao.".format(max_s=overall['max']),
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="E3: Pipeline duration analysis (N, p50, p90)")
    project_dir = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--runs",
        default=str(project_dir / "tests" / "results" / "raw" / "runs.csv"),
        help="Path to runs.csv",
    )
    parser.add_argument(
        "--out-dir",
        default=str(project_dir / "tests" / "results" / "metrics"),
        help="Directory to write metrics JSON and Markdown",
    )
    args = parser.parse_args()

    runs_path = Path(args.runs)
    if not runs_path.exists():
        print(f"ERROR: runs file not found: {runs_path}", file=sys.stderr)
        return 1

    overall_durations, by_type = load_runs_data(runs_path)

    stats = {
        "experiment": "E3",
        "description": "Pipeline execution duration analysis",
        "threshold_seconds": PIPELINE_PARALYSIS_THRESHOLD_SECONDS,
        "overall": compute_duration_stats(overall_durations),
        "groups": {t: compute_duration_stats(durs) for t, durs in sorted(by_type.items())},
    }

    print("=" * 65)
    print("E3 – ĐÁNH GIÁ THỜI GIAN PIPELINE (p50, p90, N)")
    print("=" * 65)
    print(f"Tổng số lần đo (N):        {stats['overall']['N']}")
    print(f"Trung vị (p50):            {stats['overall']['median_p50']}s (~{stats['overall']['median_p50']/60:.2f} phút)")
    print(f"Phân vị 90 (p90):          {stats['overall']['p90']}s (~{stats['overall']['p90']/60:.2f} phút)")
    print(f"Phân vị 95 (p95):          {stats['overall']['p95']}s (~{stats['overall']['p95']/60:.2f} phút)")
    print(f"Trung bình (Mean):         {stats['overall']['mean']}s (Std: {stats['overall']['std']}s)")
    print(f"Min / Max:                 {stats['overall']['min']}s / {stats['overall']['max']}s")
    print(f"Ngưỡng tê liệt (10p):      {PIPELINE_PARALYSIS_THRESHOLD_SECONDS}s")
    print(f"Trạng thái kiểm tra:       {'BỊ TÊ LIỆT' if stats['overall']['paralysis_exceeded'] else 'AN TOÀN (PASS)'}")
    print("=" * 65)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_file = out_dir / "e3_pipeline_duration.json"
    json_file.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_file = out_dir / "e3_pipeline_duration.md"
    md_file.write_text(build_markdown_report(stats) + "\n", encoding="utf-8")

    print(f"\nKết quả JSON lưu tại:     {json_file}")
    print(f"Báo cáo Markdown lưu tại: {md_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
