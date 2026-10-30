#!/usr/bin/env python3
"""
Test suite cho E1: Kiểm thử e1_detection_effectiveness.py
Chạy bằng: python -m pytest Code/DevSecOps/tests/test_e1_e2.py -v
"""

import csv
import json
import sys
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent))

from e1_detection_effectiveness import (
    load_ground_truth,
    load_ground_truth_all,
    load_findings,
    compute_metrics,
    simulate_gate_decision,
)
from e2_policy_comparison import find_best_policy, build_comparison_table
from e3_pipeline_duration import (
    percentile,
    compute_duration_stats,
    load_runs_data,
    PIPELINE_PARALYSIS_THRESHOLD_SECONDS,
)


# ────────────────────────────────────────────────────────────
# Fixtures helpers
# ────────────────────────────────────────────────────────────

def write_gt_csv(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "ground_truth.csv"
    fieldnames = ["id", "type", "category", "file", "rule_or_cve",
                  "expected_tool", "severity", "description", "author"]
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            full = {k: row.get(k, "") for k in fieldnames}
            w.writerow(full)
    return p


def write_findings_csv(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "findings.csv"
    fieldnames = ["change_id", "tool", "rule_id", "severity", "decision"]
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            full = {k: row.get(k, "") for k in fieldnames}
            w.writerow(full)
    return p


# ────────────────────────────────────────────────────────────
# Tests: simulate_gate_decision
# ────────────────────────────────────────────────────────────

def test_g0_never_blocks():
    """G0 không bao giờ chặn dù có lỗi CRITICAL."""
    findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]
    assert simulate_gate_decision(findings, "g0") == "WARN"


def test_g0_empty_findings_pass():
    """G0 với findings rỗng → PASS."""
    assert simulate_gate_decision([], "g0") == "PASS"


def test_g1_blocks_medium():
    """G1 chặn MEDIUM trở lên."""
    findings = [{"severity": "MEDIUM"}]
    assert simulate_gate_decision(findings, "g1") == "BLOCK"


def test_g1_blocks_high():
    """G1 chặn HIGH."""
    findings = [{"severity": "HIGH"}]
    assert simulate_gate_decision(findings, "g1") == "BLOCK"


def test_g1_blocks_critical():
    """G1 chặn CRITICAL."""
    findings = [{"severity": "CRITICAL"}]
    assert simulate_gate_decision(findings, "g1") == "BLOCK"


def test_g1_pass_low():
    """G1 không chặn LOW."""
    findings = [{"severity": "LOW"}]
    assert simulate_gate_decision(findings, "g1") == "WARN"


def test_g1_empty_pass():
    """G1 không có findings → PASS."""
    assert simulate_gate_decision([], "g1") == "PASS"


def test_g2_blocks_critical():
    """G2 chặn CRITICAL."""
    findings = [{"severity": "CRITICAL"}]
    assert simulate_gate_decision(findings, "g2") == "BLOCK"


def test_g2_blocks_high():
    """G2 chặn HIGH."""
    findings = [{"severity": "HIGH"}]
    assert simulate_gate_decision(findings, "g2") == "BLOCK"


def test_g2_warn_medium():
    """G2 không chặn MEDIUM (chỉ cảnh báo)."""
    findings = [{"severity": "MEDIUM"}]
    assert simulate_gate_decision(findings, "g2") == "WARN"


# ────────────────────────────────────────────────────────────
# Tests: load_ground_truth
# ────────────────────────────────────────────────────────────

def test_load_ground_truth_defects_and_cleans(tmp_path):
    rows = [
        {"id": "D01", "type": "defect", "severity": "HIGH"},
        {"id": "D02", "type": "defect", "severity": "CRITICAL"},
        {"id": "C01", "type": "clean"},
        {"id": "C02", "type": "clean"},
    ]
    gt_path = write_gt_csv(tmp_path, rows)
    defects, cleans = load_ground_truth(gt_path)
    assert set(defects.keys()) == {"D01", "D02"}
    assert cleans == {"C01", "C02"}


def test_load_ground_truth_empty(tmp_path):
    gt_path = write_gt_csv(tmp_path, [])
    defects, cleans = load_ground_truth(gt_path)
    assert defects == {}
    assert cleans == set()


# ────────────────────────────────────────────────────────────
# Tests: compute_metrics – perfect detection
# ────────────────────────────────────────────────────────────

def test_compute_metrics_perfect_g1(tmp_path):
    """Tất cả lỗi bị chặn, không chặn nhầm → recall=1, false_block=0."""
    rows_gt = [
        {"id": "D01", "type": "defect"},
        {"id": "D02", "type": "defect"},
        {"id": "C01", "type": "clean"},
    ]
    rows_f = [
        {"change_id": "D01", "severity": "HIGH"},
        {"change_id": "D02", "severity": "CRITICAL"},
        # C01 không có finding nào → PASS
    ]
    gt_path = write_gt_csv(tmp_path, rows_gt)
    findings_path = write_findings_csv(tmp_path, rows_f)
    defects, cleans = load_ground_truth(gt_path)
    findings = load_findings(findings_path)

    m = compute_metrics(defects, cleans, findings, "g1")
    assert m["recall"] == 1.0
    assert m["false_block_rate"] == 0.0
    assert m["TP"] == 2
    assert m["FN"] == 0
    assert m["FP"] == 0
    assert m["TN"] == 1


def test_compute_metrics_all_missed_g0(tmp_path):
    """G0 không chặn gì → recall=0."""
    rows_gt = [
        {"id": "D01", "type": "defect"},
        {"id": "C01", "type": "clean"},
    ]
    rows_f = [
        {"change_id": "D01", "severity": "CRITICAL"},
        {"change_id": "C01", "severity": "LOW"},
    ]
    gt_path = write_gt_csv(tmp_path, rows_gt)
    findings_path = write_findings_csv(tmp_path, rows_f)
    defects, cleans = load_ground_truth(gt_path)
    findings = load_findings(findings_path)

    m = compute_metrics(defects, cleans, findings, "g0")
    assert m["recall"] == 0.0
    assert m["TP"] == 0
    assert m["FN"] == 1


def test_compute_metrics_false_block(tmp_path):
    """Thay đổi sạch nhưng có finding HIGH bị chặn nhầm bởi G1."""
    rows_gt = [
        {"id": "C01", "type": "clean"},
    ]
    rows_f = [
        {"change_id": "C01", "severity": "HIGH"},
    ]
    gt_path = write_gt_csv(tmp_path, rows_gt)
    findings_path = write_findings_csv(tmp_path, rows_f)
    defects, cleans = load_ground_truth(gt_path)
    findings = load_findings(findings_path)

    m = compute_metrics(defects, cleans, findings, "g1")
    assert m["false_block_rate"] == 1.0
    assert m["FP"] == 1
    assert m["TN"] == 0


def test_compute_metrics_no_findings(tmp_path):
    """Không có findings nào → tất cả defects bị bỏ sót, tất cả cleans qua."""
    rows_gt = [
        {"id": "D01", "type": "defect"},
        {"id": "C01", "type": "clean"},
    ]
    gt_path = write_gt_csv(tmp_path, rows_gt)
    findings_path = write_findings_csv(tmp_path, [])
    defects, cleans = load_ground_truth(gt_path)
    findings = load_findings(findings_path)

    m = compute_metrics(defects, cleans, findings, "g1")
    assert m["TP"] == 0
    assert m["FN"] == 1
    assert m["TN"] == 1
    assert m["recall"] == 0.0
    assert m["false_block_rate"] == 0.0


# ────────────────────────────────────────────────────────────
# Tests: E2 comparison helpers
# ────────────────────────────────────────────────────────────

def test_find_best_policy_no_false_blocks():
    """Chọn policy có F1 cao nhất khi false_block_rate == 0."""
    metrics = [
        {"policy": "g0", "f1": 0.0, "false_block_rate": 0.0},
        {"policy": "g1", "f1": 0.8, "false_block_rate": 0.0},
        {"policy": "g2", "f1": 0.9, "false_block_rate": 0.0},
    ]
    assert find_best_policy(metrics) == "g2"


def test_find_best_policy_with_false_blocks():
    """Khi tất cả đều có false block, chọn policy có false_block_rate thấp nhất."""
    metrics = [
        {"policy": "g0", "f1": 0.0, "false_block_rate": 0.5},
        {"policy": "g1", "f1": 0.9, "false_block_rate": 0.2},
        {"policy": "g2", "f1": 0.8, "false_block_rate": 0.1},
    ]
    assert find_best_policy(metrics) == "g2"


def test_build_comparison_table_contains_headers():
    metrics = [
        {"policy": "g0", "recall": 0.0, "precision": 0.0, "f1": 0.0,
         "false_block_rate": 0.0, "TP": 0, "FN": 5, "FP": 0},
        {"policy": "g1", "recall": 1.0, "precision": 0.8, "f1": 0.89,
         "false_block_rate": 0.1, "TP": 5, "FN": 0, "FP": 1},
    ]
    table = build_comparison_table(metrics)
    assert "Policy" in table
    assert "Recall" in table
    assert "G0" in table
    assert "G1" in table


# ────────────────────────────────────────────────────────────
# Tests: ground_truth.csv thực tế
# ────────────────────────────────────────────────────────────

def test_real_ground_truth_has_28_defects():
    """ground_truth.csv thực tế phải có đúng 28 lỗi gieo cài."""
    gt_path = Path(__file__).parents[1] / "ground_truth" / "ground_truth.csv"
    if not gt_path.exists():
        pytest.skip("ground_truth.csv chưa có trong repo")
    defects, cleans = load_ground_truth(gt_path)
    assert len(defects) == 28, f"Mong đợi 28 defects, thực tế {len(defects)}"


def test_real_ground_truth_has_10_cleans():
    """ground_truth.csv thực tế phải có đúng 10 thay đổi sạch."""
    gt_path = Path(__file__).parents[1] / "ground_truth" / "ground_truth.csv"
    if not gt_path.exists():
        pytest.skip("ground_truth.csv chưa có trong repo")
    defects, cleans = load_ground_truth(gt_path)
    assert len(cleans) == 10, f"Mong đợi 10 cleans, thực tế {len(cleans)}"


def test_real_ground_truth_has_8_controls():
    """ground_truth.csv thực tế phải có đúng 8 mẫu đối chứng."""
    gt_path = Path(__file__).parents[1] / "ground_truth" / "ground_truth.csv"
    if not gt_path.exists():
        pytest.skip("ground_truth.csv chưa có trong repo")
    defects, cleans, controls = load_ground_truth_all(gt_path)
    assert len(controls) == 8, f"Mong đợi 8 controls, thực tế {len(controls)}"
    assert set(controls.keys()) == {f"N{i:02d}" for i in range(1, 9)}


def test_real_ground_truth_ids_unique():
    """Tất cả 46 ID trong ground_truth.csv (28 defects + 10 cleans + 8 controls) phải duy nhất."""
    gt_path = Path(__file__).parents[1] / "ground_truth" / "ground_truth.csv"
    if not gt_path.exists():
        pytest.skip("ground_truth.csv chưa có trong repo")
    defects, cleans, controls = load_ground_truth_all(gt_path)
    all_ids = list(defects.keys()) + list(cleans) + list(controls.keys())
    assert len(all_ids) == 46, f"Mong đợi tổng cộng 46 IDs, thực tế {len(all_ids)}"
    assert len(all_ids) == len(set(all_ids)), "Có ID trùng trong ground_truth.csv"


# ────────────────────────────────────────────────────────────
# Tests: E3 pipeline duration & percentile stats
# ────────────────────────────────────────────────────────────

def test_e3_percentile_calculation():
    """Kiểm tra tính toán phân vị p50, p90 chính xác."""
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    p50 = percentile(data, 50.0)
    p90 = percentile(data, 90.0)
    assert p50 == 55.0
    assert p90 == 91.0


def test_e3_compute_duration_stats():
    """Kiểm tra compute_duration_stats trả về đầy đủ N, mean, median, p90, min, max."""
    data = [100.0, 120.0, 140.0, 160.0, 180.0]
    stats = compute_duration_stats(data)
    assert stats["N"] == 5
    assert stats["median_p50"] == 140.0
    assert stats["min"] == 100.0
    assert stats["max"] == 180.0
    assert stats["paralysis_exceeded"] is False


def test_e3_real_runs_has_38_records():
    """Tập dữ liệu runs.csv thực tế phải có đủ 38 lần chạy."""
    runs_path = Path(__file__).parents[1] / "tests" / "results" / "raw" / "runs.csv"
    if not runs_path.exists():
        pytest.skip("runs.csv chưa có trong repo")
    overall, by_type = load_runs_data(runs_path)
    assert len(overall) == 38, f"Mong đợi 38 lần chạy, thực tế {len(overall)}"
    assert len(by_type["defect"]) == 28
    assert len(by_type["clean"]) == 10


def test_e3_real_runs_not_exceed_paralysis():
    """Thời gian chạy pipeline thực tế không được vượt quá ngưỡng tê liệt (600 giây)."""
    runs_path = Path(__file__).parents[1] / "tests" / "results" / "raw" / "runs.csv"
    if not runs_path.exists():
        pytest.skip("runs.csv chưa có trong repo")
    overall, _ = load_runs_data(runs_path)
    stats = compute_duration_stats(overall)
    assert stats["paralysis_exceeded"] is False
    assert stats["max"] < PIPELINE_PARALYSIS_THRESHOLD_SECONDS

