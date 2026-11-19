"""Vẽ hình và bảng tổng hợp cho báo cáo từ gói bằng chứng live (mặc định: live-evidence-2026-11-16).

Chỉ đọc các JSON đã có trong gói bằng chứng và ground_truth.csv, không gọi mạng.
Chạy: python Code/DevSecOps/tests/plot_live_evidence.py
Kết quả: tests/results/figures/live-2026-11-16/ gồm 4 hình PNG và e2_full_delta.csv.
Tùy chọn --report: hình khổ nhỏ, bỏ tiêu đề và chú thích (đã có trong chú thích hình của báo cáo).
"""

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

PROJECT_DIR = Path(__file__).resolve().parents[1]
RESULTS = PROJECT_DIR / "tests" / "results"
GROUND_TRUTH = PROJECT_DIR / "ground_truth" / "ground_truth.csv"
REPORT = False
BLUE, ORANGE, AQUA, INK, INK2 = "#2a78d6", "#eb6834", "#1baf7a", "#0b0b0b", "#52514e"
LAYERS = [("sast", "SAST (Semgrep)"), ("secret", "Secret (Gitleaks)"), ("sca", "SCA (Trivy)"),
          ("image", "Dockerfile (Checkov)"), ("iac", "Terraform (Checkov)"),
          ("k8s", "Kubernetes (Checkov, Trivy)"), ("workflow", "Workflow (Conftest)")]
JOBS = [("Prepare Trivy and Grype vulnerability DB snapshots", "DB lỗ hổng"), ("Run Python tests", "Test"),
        ("Security scans (collection mode)", "Quét mã"), ("iac", "IaC"), ("image", "Image"),
        ("gate (Conftest Rego)", "Gate")]


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def style(ax, xlabel="", ylabel="", grid="y"):
    ax.set_xlabel(xlabel, color=INK2)
    ax.set_ylabel(ylabel, color=INK2)
    ax.grid(axis=grid, color="#e4e3df", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=INK2)


THOUSANDS = FuncFormatter(lambda v, _: f"{v:,.0f}".replace(",", "."))


def size(normal, report):
    return report if REPORT else normal


def title(target, text, **kw):
    if not REPORT:
        (target.suptitle if hasattr(target, "suptitle") else target.set_title)(text, color=INK, **kw)


def footnote(fig, text):
    if REPORT:
        return
    fig.canvas.draw()
    box = fig.get_tightbbox(fig.canvas.get_renderer())
    fig.text(box.x0 / fig.get_figwidth(), box.y0 / fig.get_figheight() - 0.03, text,
             fontsize=7.5, color=INK2, ha="left", va="top")


def e2_modes(cases):
    """Đếm số mẫu bị BLOCK theo chính sách, chế độ (full/delta) và loại mẫu (D/C/N)."""
    rows = []
    groups = {"defect": "D", "clean": "C", "control": "N"}
    for mode, key in (("full", "policy_decisions"), ("delta", "incremental_policy_actions")):
        for policy in ("g0", "g1", "g2"):
            for sample_type, label in groups.items():
                subset = [c for c in cases if c["sample_type"] == sample_type]
                blocked = sum(1 for c in subset if c[key][policy] == "BLOCK")
                warned = sum(1 for c in subset if c[key][policy] == "WARN")
                rows.append({"mode": mode, "policy": policy.upper(), "sample": label, "n": len(subset),
                             "block": blocked, "warn": warned})
    return rows


def plot_e1(out, cases, truth, note):
    defects = [c for c in cases if c["sample_type"] == "defect"]
    fig, ax = plt.subplots(figsize=size((8.6, 3.4), (6.0, 2.5)))
    ids = [c["fixture_id"] for c in defects]
    vals = [c["new_findings_count"] for c in defects]
    ax.bar(range(len(ids)), vals, color=BLUE, width=0.7)
    for i, v in enumerate(vals):
        ax.text(i, v + 0.3, str(v), ha="center", va="bottom", fontsize=7, color=INK)
    ax.set_xticks(range(len(ids)), ids, rotation=90, fontsize=7.5)
    # vạch chia theo lớp kiểm tra
    start = 0
    for layer, label in LAYERS:
        n = sum(1 for c in defects if truth[c["fixture_id"]]["category"] == layer)
        if n == 0:
            continue
        ax.axvline(start - 0.5, color="#c9c8c2", linewidth=0.8)
        ax.text(start + (n - 1) / 2, max(vals) * 1.18, label.split(" (")[0], ha="center", fontsize=size(7.5, 6.5), color=INK2)
        start += n
    ax.set_ylim(0, max(vals) * 1.3)
    style(ax, "", "Số finding mới so với baseline")
    title(ax, "E1 - Finding mới trên từng lỗi gieo cài (28/28 có finding đúng rule đích)", loc="left", fontsize=10)
    footnote(fig, note)
    fig.savefig(out / "e1_new_findings_per_defect.png")
    plt.close(fig)


def plot_e2(out, rows, note):
    fig, axes = plt.subplots(1, 2, figsize=size((9.2, 3.8), (6.0, 2.5)), sharey=True)
    series = (("D", BLUE, "", "Lỗi gieo cài D (n = 28)"), ("C", ORANGE, "///", "Thay đổi sạch C (n = 10)"),
              ("N", AQUA, "\\\\\\", "Mẫu đối chứng N (n = 8)"))
    for ax, mode in zip(axes, ("full", "delta")):
        for i, policy in enumerate(("G0", "G1", "G2")):
            for k, (sample, color, hatch, _) in enumerate(series):
                r = next(x for x in rows if x["mode"] == mode and x["policy"] == policy and x["sample"] == sample)
                value = 100 * r["block"] / r["n"]
                x = i + (k - 1) * 0.29
                ax.bar(x, value, width=0.27, color=color, hatch=hatch, edgecolor="white")
                ax.text(x, value + 2, f"{r['block']}/{r['n']}", ha="center", va="bottom", fontsize=6.5,
                        rotation=size(0, 90), color=INK)
        ax.set_xticks(range(3), ["G0", "G1", "G2"])
        ax.set_ylim(0, size(115, 128))
        ax.set_yticks(range(0, 101, 20))
        style(ax, "Chính sách", "Tỷ lệ mẫu bị chặn (%)" if mode == "full" else "")
        ax.set_title(f"Chế độ {mode}", color=INK, loc="left")
    handles = [Patch(facecolor=c, hatch=h, edgecolor="white") for _, c, h, _ in series]
    fig.legend(handles, [s[3] for s in series], loc="lower center", ncol=3, frameon=False, fontsize=size(8, 7),
               bbox_to_anchor=(0.5, size(-0.11, -0.16)))
    title(fig, "E2 - Quyết định gate trên cùng bộ quan sát", x=0.01, ha="left", y=1.0)
    footnote(fig, note)
    fig.savefig(out / "e2_block_rates_full_delta.png")
    plt.close(fig)


def plot_e3(out, e3, note):
    cold, warm = e3["profiles"]["cold"], e3["profiles"]["warm"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=size((8.6, 3.6), (6.0, 2.4)), gridspec_kw={"width_ratios": [2, 5]})
    for i, (prof, color) in enumerate(((cold, BLUE), (warm, ORANGE))):
        w = prof["workflow_wall_seconds"]
        ax1.bar(i, w["median"], color=color, width=0.6)
        ax1.errorbar(i, w["median"], yerr=[[w["median"] - w["q1"]], [w["q3"] - w["median"]]], color=INK,
                     capsize=4, linewidth=1)
        ax1.text(i, w["q3"] + 3, f"{w['median']:.0f} s", ha="center", va="bottom", fontsize=8, color=INK)
    ax1.set_xticks([0, 1], ["Cold", "Warm"])
    ax1.set_xlim(-0.6, 1.6)
    ax1.set_ylim(0, 150)
    style(ax1, "Cache pip", "Giây")
    ax1.set_title(size("Thời gian tường (trung vị, IQR)", "Thời gian tường"), color=INK, loc="left", fontsize=9)
    for k, (prof, color, label) in enumerate(((cold, BLUE, "Cold"), (warm, ORANGE, "Warm"))):
        meds = [prof["per_job_seconds"][j]["median"] for j, _ in JOBS]
        xs = [i + (k - 0.5) * 0.38 for i in range(len(JOBS))]
        ax2.bar(xs, meds, width=0.36, color=color, label=label)
        for x, v in zip(xs, meds):
            ax2.text(x, v + 0.8, f"{v:.0f}", ha="center", va="bottom", fontsize=7, color=INK)
    ax2.set_xticks(range(len(JOBS)), [lbl for _, lbl in JOBS], fontsize=8)
    style(ax2, "", "")
    ax2.legend(frameon=False, fontsize=8, loc="upper left")
    ax2.set_title(size("Trung vị thời gian từng job (giây)", "Trung vị từng job (giây)"), color=INK, loc="left",
                  fontsize=9)
    title(fig, "E3 - Thời gian pipeline theo trạng thái cache pip (mỗi cấu hình n = 5)", x=0.01, ha="left", y=1.02)
    footnote(fig, note)
    fig.savefig(out / "e3_cache_cold_warm.png")
    plt.close(fig)


def plot_e4(out, e4, note):
    live = e4["live"]
    sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=size((8.6, 3.5), (6.0, 2.4)), gridspec_kw={"width_ratios": [4, 2]})
    for k, (side, color, hatch, label) in enumerate((("before", BLUE, "", "Trước (Dockerfile.vuln)"),
                                                     ("after", ORANGE, "///", "Sau (Dockerfile)"))):
        vals = [live[side]["vulnerabilities"][s] for s in sev]
        xs = [i + (k - 0.5) * 0.38 for i in range(len(sev))]
        ax1.bar(xs, vals, width=0.36, color=color, hatch=hatch, edgecolor="white", label=label)
        for x, v in zip(xs, vals):
            ax1.text(x, v + 25, f"{v:,}".replace(",", "."), ha="center", va="bottom", fontsize=7, color=INK)
    ax1.set_xticks(range(len(sev)), sev, fontsize=8)
    ax1.set_ylim(0, max(live["before"]["vulnerabilities"][s] for s in sev) * 1.4)
    ax1.yaxis.set_major_formatter(THOUSANDS)
    style(ax1, "Mức độ (Trivy)", "Số bản ghi lỗ hổng")
    ax1.legend(frameon=False, fontsize=size(8, 7), loc="upper left")
    ax1.set_title("Lỗ hổng theo mức độ", color=INK, loc="left", fontsize=9)
    vals = [live["before"]["sbom_packages"], live["after"]["sbom_packages"]]
    ax2.bar([0, 1], vals, color=[BLUE, ORANGE], hatch=["", "///"], edgecolor="white", width=0.6)
    for i, v in enumerate(vals):
        ax2.text(i, v + 300, f"{v:,}".replace(",", "."), ha="center", va="bottom", fontsize=8, color=INK)
    ax2.set_xticks([0, 1], ["Trước", "Sau"])
    ax2.set_ylim(0, max(vals) * 1.18)
    ax2.yaxis.set_major_formatter(THOUSANDS)
    style(ax2, "", "Thành phần trong SBOM")
    ax2.set_title("SBOM (Syft)", color=INK, loc="left", fontsize=9)
    title(fig, "E4 - Image trước và sau khắc phục", x=0.01, ha="left", y=1.02)
    footnote(fig, note)
    fig.savefig(out / "e4_image_before_after.png")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=str(RESULTS / "metrics" / "live-evidence-2026-11-16"))
    parser.add_argument("--out", default=str(RESULTS / "figures" / "live-2026-11-16"))
    parser.add_argument("--report", action="store_true", help="hình khổ nhỏ cho báo cáo, không tiêu đề và chú thích")
    args = parser.parse_args()
    global REPORT
    REPORT = args.report
    ev, out = Path(args.evidence), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 8 if REPORT else 9, "figure.dpi": 220 if REPORT else 150, "savefig.bbox": "tight"})

    with GROUND_TRUTH.open(encoding="utf-8") as fh:
        truth = {r["id"]: r for r in csv.DictReader(fh)}
    e12 = load(ev / "e1_e2_live_observations.json")
    e3 = load(ev / "e3_live_cache_comparison.json")
    e4 = load(ev / "e4_image_remediation.json")
    commit = e12["baseline_commit"][:7]

    rows = e2_modes(e12["cases"])
    with (out / "e2_full_delta.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    base = f"Commit {commit}, GitHub-hosted ubuntu-24.04, mỗi mẫu một lượt chạy riêng ghép với baseline cùng commit."
    plot_e1(out, e12["cases"], truth, base + " Chi tiết: e1_e2_live_observations.json.")
    plot_e2(out, rows, base + " Full: chấm toàn bộ finding; delta: chỉ finding mới so với baseline.")
    plot_e3(out, e3, f"Commit {commit}, 5 lượt cold và 5 lượt warm, cùng phiên bản công cụ và snapshot DB 20261115-v1;"
                     " một lượt làm nóng bị loại. Release và deploy-smoke không chạy khi dispatch.")
    plot_e4(out, e4, f"Run {e4['live']['provenance']['ci_run_id']}, commit {commit}; cùng Python 3.13.18, Debian 13.7,"
                     " amd64, Trivy 0.76.1 và DB cập nhật 2026-11-15.")
    print(f"Đã ghi {out}")


if __name__ == "__main__":
    main()
