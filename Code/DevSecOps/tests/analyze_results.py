import argparse
import csv
import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

PROJECT_DIR = Path(__file__).resolve().parents[1]
RESULTS = PROJECT_DIR / "tests" / "results"
GROUND_TRUTH = PROJECT_DIR / "ground_truth" / "ground_truth.csv"
BLUE, ORANGE, AQUA, INK, INK2 = "#2a78d6", "#eb6834", "#1baf7a", "#0b0b0b", "#52514e"

# Phạm vi của từng công cụ theo lớp phát hiện trong bộ đáp án (recall "trong phạm vi").
TOOL_SCOPE = {
    "semgrep": {"sast"}, "semgrep-registry": {"sast"}, "gitleaks": {"secret"},
    "trivy-fs": {"sca"}, "trivy-image": {"image"}, "trivy-config": {"dockerfile", "iac", "k8s"},
    "checkov": {"dockerfile", "iac", "k8s", "workflow"}, "conftest": {"workflow"},
}


def read_csv(path):
    with Path(path).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def latest(pattern):
    found = sorted((RESULTS / "raw").glob(pattern))
    return found[-1] if found else None


def tool_label(row):
    if row["tool"] != "trivy":
        return row["tool"]
    if row["category"] == "image" and row["rule_id"].startswith("CVE-"):
        return "trivy-image"
    return "trivy-fs" if row["category"] == "sca" else "trivy-config"


def matches(row, gt):
    accepted = [a for a in gt["accepted_rule_ids"].split(";") if a]
    if gt["scan_target"] == "image":
        return row["category"] == "image" and any(
            row["rule_id"].startswith(a.rstrip("*")) for a in accepted)
    target = gt["scan_target"].rsplit("/", 1)[-1]
    return row["rule_id"] in accepted and row["file"].endswith(target)


def frac(k, n):
    return f"{k}/{n} ({100 * k / n:.1f} %)" if n else "0/0"


def e1(findings, truth):
    new = {}
    for r in findings:
        if r["in_baseline"] == "0" and r["change_id"] != "BASE":
            new.setdefault(r["change_id"], []).append(r)
    defects = [g for g in truth if g["type"] == "defect"]
    per_defect, extra = [], []
    for g in defects:
        rows = new.get(g["id"], [])
        tools = sorted({tool_label(r) for r in rows if matches(r, g)})
        per_defect.append({"id": g["id"], "detect_layer": g["detect_layer"], "detected": int(bool(tools)),
                           "detected_by": ";".join(tools), "accepted_rule_ids": g["accepted_rule_ids"],
                           "new_findings": len(rows), "cach_sua": g["fix"]})
        extra += [r for r in rows if not matches(r, g)]
    by_tool = []
    for tool, scope in TOOL_SCOPE.items():
        in_scope = [d for d in per_defect if d["detect_layer"] in scope]
        hit = [d for d in in_scope if tool in d["detected_by"].split(";")]
        by_tool.append({"tool": tool, "scope": "+".join(sorted(scope)), "detected": len(hit),
                        "in_scope": len(in_scope), "recall_in_scope": frac(len(hit), len(in_scope)),
                        "recall_all_28": frac(len(hit), len(defects))})
    controls = []
    for g in (g for g in truth if g["type"] == "control"):
        rows = new.get(g["id"], [])
        target = [r for r in rows if matches(r, g)]
        controls.append({"id": g["id"], "target_rule_reported": int(bool(target)),
                         "other_new_findings": len(rows) - len(target)})
    clean_new = {g["id"]: len(new.get(g["id"], [])) for g in truth if g["type"] == "clean"}
    severity = {}
    for r in extra:
        severity[r["severity"]] = severity.get(r["severity"], 0) + 1
    return per_defect, by_tool, controls, clean_new, severity


def e2(decisions, truth):
    expected = {g["id"]: g["expected_g2"] for g in truth}
    rows = []
    for policy in ("g0", "g1", "g2"):
        for mode in ("full", "delta"):
            sel = [d for d in decisions if d["policy"] == policy and d["mode"] == mode]
            by_type = lambda t: [d for d in sel if d["type"] == t]  # noqa: E731
            d_rows, c_rows, n_rows = by_type("defect"), by_type("clean"), by_type("control")
            block_tier = [d for d in d_rows if expected.get(d["change_id"]) == "BLOCK"]
            warns = [int(d["warn_count"]) for d in d_rows + c_rows]
            rows.append({
                "policy": policy, "mode": mode,
                "block_rate": frac(sum(d["decision"] == "BLOCK" for d in d_rows), len(d_rows)),
                "false_block_rate": frac(sum(d["decision"] == "BLOCK" for d in c_rows), len(c_rows)),
                "block_tier_blocked": frac(sum(d["decision"] == "BLOCK" for d in block_tier), len(block_tier)),
                "controls_blocked": frac(sum(d["decision"] == "BLOCK" for d in n_rows), len(n_rows)),
                "warn_per_pr_median": statistics.median(warns) if warns else 0,
                "warn_per_pr_max": max(warns) if warns else 0,
                "_block": sum(d["decision"] == "BLOCK" for d in d_rows) / max(len(d_rows), 1),
                "_false": sum(d["decision"] == "BLOCK" for d in c_rows) / max(len(c_rows), 1),
                "_tier_all": all(d["decision"] == "BLOCK" for d in block_tier),
                "_false_n": sum(d["decision"] == "BLOCK" for d in c_rows),
            })
    return rows


def percentile(values, q):
    values = sorted(values)
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def e3(runs):
    out = {}
    for mode in ("c1_seq_nocache", "c2_par_nocache", "c3_par_cache"):
        sel = [r for r in runs if r["mode"] == mode and r["conclusion"] == "success"]
        if mode == "c3_par_cache":
            sel = [r for r in sel if r["rep"] != "1"]  # lượt 1 của C3 là cache lạnh
        wall = [float(r["wall_seconds"]) for r in sel]
        jobs = [float(r["job_seconds_total"]) / 60 for r in sel]
        if wall:
            out[mode] = {"mode": mode, "n": len(wall), "median_s": round(statistics.median(wall), 1),
                         "p90_s": round(percentile(wall, 0.9), 1), "min_s": min(wall), "max_s": max(wall),
                         "job_minutes_median": round(statistics.median(jobs), 2), "_wall": wall}
    return out


def style(ax, xlabel, ylabel):
    ax.set_xlabel(xlabel, color=INK2)
    ax.set_ylabel(ylabel, color=INK2)
    ax.grid(axis="x" if ax.get_xlim()[1] > 1 else "y", color="#e4e3df", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=INK2)


def figures(out, by_tool, e2_rows, e3_rows, e4_rows, meta):
    plt.rcParams.update({"font.size": 10, "figure.dpi": 150, "savefig.bbox": "tight"})
    # E1: recall trong phạm vi từng công cụ (cột ngang, nhãn phân số).
    fig, ax = plt.subplots(figsize=(7, 3.6))
    tools = [t for t in by_tool if t["in_scope"]][::-1]
    vals = [t["detected"] / t["in_scope"] * 100 for t in tools]
    ax.barh([t["tool"] for t in tools], vals, color=BLUE, height=0.6)
    for y, t in enumerate(tools):
        ax.text(min(vals[y] + 2, 92), y, f"{t['detected']}/{t['in_scope']}", va="center", color=INK)
    ax.set_xlim(0, 105)
    style(ax, "Recall trong phạm vi công cụ (%)", "")
    ax.set_title(f"E1 – Lỗi gieo cài bắt được theo công cụ (n = 28 lỗi, {meta})", color=INK, loc="left")
    fig.savefig(out / "e1_recall_by_tool.png")
    plt.close(fig)
    # E2: tỷ lệ chặn đúng và chặn nhầm theo chính sách và chế độ.
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.4), sharey=True)
    labels = ["G0", "G1", "G2"]
    for ax, mode in zip(axes, ("full", "delta")):
        sel = [r for r in e2_rows if r["mode"] == mode]
        x = range(len(sel))
        ax.bar([i - 0.2 for i in x], [r["_block"] * 100 for r in sel], width=0.38, color=BLUE,
               label="Chặn lỗi D (n = 28)")
        ax.bar([i + 0.2 for i in x], [r["_false"] * 100 for r in sel], width=0.38, color=ORANGE,
               hatch="///", edgecolor="white", label="Chặn nhầm C (n = 10)")
        ax.set_xticks(list(x), labels)
        ax.set_ylim(0, 105)
        style(ax, "Chính sách", "Tỷ lệ (%)" if mode == "full" else "")
        ax.set_title(f"Chế độ {mode}", color=INK, loc="left")
    axes[1].legend(frameon=False, loc="upper right")
    fig.suptitle(f"E2 – Quyết định gate trên cùng bộ findings ({meta})", color=INK, x=0.01, ha="left")
    fig.savefig(out / "e2_block_rates.png")
    plt.close(fig)
    if e3_rows:
        fig, ax = plt.subplots(figsize=(6, 3.4))
        modes = list(e3_rows)
        ax.boxplot([e3_rows[m]["_wall"] for m in modes], widths=0.5,
                   medianprops={"color": ORANGE, "linewidth": 2})
        ax.set_xticks(range(1, len(modes) + 1), [f"{m.split('_')[0].upper()}\n(n = {e3_rows[m]['n']})" for m in modes])
        style(ax, "Cấu hình pipeline", "Thời gian tường (s)")
        ax.set_title("E3 – Thời gian pipeline theo cấu hình (GitHub-hosted ubuntu-24.04)", color=INK, loc="left")
        fig.savefig(out / "e3_timing.png")
        plt.close(fig)
    if e4_rows:
        before, after = e4_rows
        panels = [("Kích thước (MB)", "size_mb"), ("Gói trong SBOM", "sbom_packages"),
                  ("CVE duy nhất", "unique_cves"), ("CVE CRITICAL/HIGH có bản vá", "crit_high_fixable")]
        fig, axes = plt.subplots(1, 4, figsize=(10, 3))
        for ax, (title, key) in zip(axes, panels):
            vals = [float(before[key]), float(after[key])]
            ax.bar(["Trước", "Sau"], vals, color=[BLUE, ORANGE], hatch=["", "///"], edgecolor="white", width=0.6)
            for i, v in enumerate(vals):
                ax.text(i, v, f"{v:g}", ha="center", va="bottom", color=INK)
            ax.set_title(title, color=INK, fontsize=9)
            style(ax, "", "")
        fig.suptitle("E4 – Image trước (Dockerfile.vuln) và sau khắc phục (Dockerfile), cùng Trivy DB",
                     color=INK, x=0.01, ha="left")
        fig.savefig(out / "e4_before_after.png")
        plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exp", type=Path, default=None, help="thư mục exp_<ngày>_<run> (mặc định: mới nhất)")
    parser.add_argument("--e3", type=Path, default=None, help="thư mục e3_<ngày>_<run> (mặc định: mới nhất)")
    args = parser.parse_args()
    exp = args.exp or latest("exp_*")
    e3_dir = args.e3 or latest("e3_*")
    if exp is None:
        raise SystemExit("chưa có dữ liệu thực nghiệm trong tests/results/raw/exp_*")
    truth = read_csv(GROUND_TRUTH)
    samples = read_csv(exp / "samples.csv")
    run_url = samples[0]["run_url"]
    meta = f"run {samples[0]['run_id']}"
    metrics, figs = RESULTS / "metrics", RESULTS / "figures"
    metrics.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)

    per_defect, by_tool, controls, clean_new, severity = e1(read_csv(exp / "findings_all.csv"), truth)
    e2_rows = e2(read_csv(exp / "decisions.csv"), truth)
    e3_rows = e3(read_csv(e3_dir / "runs.csv")) if e3_dir else {}
    e4_rows = read_csv(exp / "e4_images.csv") if (exp / "e4_images.csv").exists() else []
    e3_url = ""
    if e3_dir:
        e3_meta = json.loads((e3_dir / "meta.json").read_text(encoding="utf-8"))
        e3_url = f"{run_url.rsplit('/runs/', 1)[0]}/runs/{e3_meta['orchestrator_run']}"

    write_csv(metrics / "e1_detection_by_defect.csv", per_defect)
    write_csv(metrics / "e1_recall_by_tool.csv", by_tool)
    write_csv(metrics / "e1_controls.csv", controls)
    write_csv(metrics / "e2_policy_comparison.csv", [{k: v for k, v in r.items() if not k.startswith("_")} for r in e2_rows])
    if e3_rows:
        write_csv(metrics / "e3_timing.csv", [{k: v for k, v in r.items() if not k.startswith("_")} for r in e3_rows.values()])
    figures(figs, by_tool, e2_rows, e3_rows, e4_rows, meta)

    detected = sum(d["detected"] for d in per_defect)
    best = max(by_tool, key=lambda t: t["detected"])
    g = {(r["policy"], r["mode"]): r for r in e2_rows}
    src_e1, src_e2 = f"{exp.name}/findings_all.csv", f"{exp.name}/decisions.csv"
    rows = [
        ("E1_RECALL_KET_HOP", frac(detected, 28), "lỗi", 28, "lỗi D có ít nhất một finding mới khớp rule chấp nhận và tệp đích", src_e1, run_url),
        ("E1_RECALL_CONG_CU_CAO_NHAT", f"{best['tool']}: {best['recall_all_28']}", "lỗi", 28, "số lỗi D một công cụ bắt được trên 28", src_e1, run_url),
        ("E1_N_BAO_DUNG_RULE_DICH", frac(sum(c["target_rule_reported"] for c in controls), 8), "mẫu", 8, "mẫu N có finding mới đúng rule đích của lỗi tương ứng", src_e1, run_url),
        ("E1_C_CO_FINDING_MOI", frac(sum(1 for v in clean_new.values() if v), 10), "thay đổi", 10, "thay đổi sạch có finding mới so với baseline", src_e1, run_url),
        ("E1_FINDING_NGOAI_DAP_AN", json.dumps(severity, ensure_ascii=False), "finding", "", "finding mới trên mẫu D không khớp đáp án, theo mức", src_e1, run_url),
    ]
    for (policy, mode), r in sorted(g.items()):
        tag = f"E2_{policy.upper()}_{mode.upper()}"
        rows += [
            (f"{tag}_BLOCK_RATE", r["block_rate"], "lỗi", 28, "mẫu D bị gate trả BLOCK", src_e2, run_url),
            (f"{tag}_FALSE_BLOCK", r["false_block_rate"], "thay đổi", 10, "mẫu C bị gate trả BLOCK", src_e2, run_url),
            (f"{tag}_WARN_TRUNG_VI", r["warn_per_pr_median"], "cảnh báo/PR", 38, "trung vị số WARN trên D+C", src_e2, run_url),
            (f"{tag}_WARN_LON_NHAT", r["warn_per_pr_max"], "cảnh báo/PR", 38, "lớn nhất số WARN trên D+C", src_e2, run_url),
        ]
    for mode in ("c1_seq_nocache", "c2_par_nocache", "c3_par_cache"):
        r = e3_rows.get(mode)
        tag = f"E3_{mode.split('_')[0].upper()}"
        rows += [(f"{tag}_TRUNG_VI", r["median_s"] if r else "CHUA_DO", "s", r["n"] if r else "", "trung vị thời gian tường", "e3/runs.csv", e3_url),
                 (f"{tag}_P90", r["p90_s"] if r else "CHUA_DO", "s", r["n"] if r else "", "phân vị 90 thời gian tường", "e3/runs.csv", e3_url)]
    if e4_rows:
        b, a = e4_rows
        for key, unit in (("size_mb", "MB"), ("sbom_packages", "gói"), ("unique_cves", "CVE"),
                          ("crit_high_fixable", "CVE"), ("kev_cves", "CVE")):
            rows += [(f"E4_{key.upper()}_TRUOC", b[key], unit, "", "image Dockerfile.vuln", f"{exp.name}/e4_images.csv", run_url),
                     (f"E4_{key.upper()}_SAU", a[key], unit, "", "image Dockerfile", f"{exp.name}/e4_images.csv", run_url)]

    h = []
    single_max = max(t["detected"] for t in by_tool)
    h.append(("H1", "ủng hộ" if single_max < 14 and detected >= 24 else "bác bỏ",
              f"công cụ đơn lẻ cao nhất {single_max}/28; kết hợp {detected}/28 (ngưỡng 14/28 và 24/28)"))
    for mode in ("full", "delta"):
        g1, g2 = g[("g1", mode)], g[("g2", mode)]
        ok = g1["_false"] >= 0.5 and g2["_false_n"] == 0 and g2["_tier_all"]
        h.append((f"H2 ({mode})", "ủng hộ" if ok else "bác bỏ",
                  f"G1 chặn nhầm {g1['false_block_rate']}; G2 chặn nhầm {g2['false_block_rate']}, chặn tầng BLOCK {g2['block_tier_blocked']}"))
    if "c1_seq_nocache" in e3_rows and "c3_par_cache" in e3_rows:
        c1, c3 = e3_rows["c1_seq_nocache"]["median_s"], e3_rows["c3_par_cache"]["median_s"]
        h.append(("H3", "ủng hộ" if c3 <= 0.7 * c1 else "bác bỏ", f"trung vị C1 {c1} s, C3 {c3} s ({100 * (c1 - c3) / c1:.1f} % nhanh hơn)"))
    else:
        h.append(("H3", "chưa đủ dữ liệu", "CHUA_DO"))
    if e4_rows:
        b, a = e4_rows
        cb, ca = int(b["crit_high_fixable"]), int(a["crit_high_fixable"])
        ok = ca <= cb / 2 and float(a["size_mb"]) < float(b["size_mb"])
        h.append(("H4", "ủng hộ" if ok else "bác bỏ", f"CRITICAL/HIGH có bản vá {cb} → {ca}; kích thước {b['size_mb']} → {a['size_mb']} MB"))
    write_csv(metrics / "hypotheses.csv", [{"gia_thuyet": a, "ket_luan": b, "can_cu": c} for a, b, c in h])
    write_csv(metrics / "so_lieu_bao_cao.csv", [dict(zip(
        ("ma_so", "gia_tri", "don_vi", "n", "cach_tinh", "tep_nguon", "run_url"), r)) for r in rows])
    for a, b, c in h:
        print(f"{a}: {b} – {c}")
    print(f"CHUA_DO: {sum(1 for r in rows if r[1] == 'CHUA_DO')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
