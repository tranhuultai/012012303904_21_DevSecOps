#!/usr/bin/env python3
"""
E4 – Ảnh hưởng của khắc phục lên image và SBOM (phần của Tài, RQ5 của Long).

Ba lớp phân tích:
  1. Cấu trúc Dockerfile (luôn chạy, không cần daemon):
     so sánh lab/docker/Dockerfile.vuln (trước khắc phục) với Dockerfile
     (sau khắc phục) theo 4 chiều kiểm soát: USER không root, không ADD từ
     URL, không sshd/cổng 22, multi-stage thay cho base đầy đủ.
  2. Độ nhạy chính sách (RQ5): với cùng một tập phát hiện, quyết định của G2
     thay đổi thế nào khi tín hiệu KEV/EPSS thay đổi. T0 là dữ liệu mô phỏng,
     T1 lấy từ tập dữ liệu đã kiểm chứng trong security/kev/; đây không phải
     phép đo lịch sử hay bằng chứng về trạng thái thật của CVE tại T0.
  3. Chế độ live (tự bật khi có docker + trivy + syft): build hai image,
     quét Trivy và xuất SBOM Syft, so sánh số gói và số lỗ hổng theo mức.

Đầu ra: results/metrics/e4_image_remediation.json và .md
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_DIR = Path(__file__).resolve().parents[1]


# ─────────────────────────────────────────────────────────────
# 1) Phân tích cấu trúc Dockerfile
# ─────────────────────────────────────────────────────────────

def dockerfile_checks(path: Path) -> dict:
    """Trích 4 chiều kiểm soát khắc phục từ một Dockerfile."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines()]

    user_directives = [
        ln for ln in lines if ln.upper().startswith("USER ")
    ]
    non_root = any(
        part not in {"root", "0"}
        for ln in user_directives
        for part in [ln.split(None, 1)[1].strip().lower()]
    )
    add_remote = any(
        ln.upper().startswith("ADD ") and ("http://" in ln or "https://" in ln)
        for ln in lines
    )
    sshd = any("openssh-server" in ln for ln in lines)
    expose_22 = any(
        ln.upper().startswith("EXPOSE ") and "22" in ln.split()
        for ln in lines
    )
    multi_stage = any(
        ln.upper().startswith("FROM ") and " as " in ln.lower()
        for ln in lines
    )

    return {
        "non_root_user": non_root,
        "no_add_remote": not add_remote,
        "no_sshd_or_port22": not (sshd or expose_22),
        "multi_stage": multi_stage,
    }


def structural_comparison(before: Path, after: Path) -> dict:
    checks_before = dockerfile_checks(before)
    checks_after = dockerfile_checks(after)
    remediated = [
        key for key in checks_before
        if checks_before[key] is False and checks_after[key] is True
    ]
    return {
        "before": {"file": before.name, **checks_before},
        "after": {"file": after.name, **checks_after},
        "remediated_controls": sorted(remediated),
        "remediated_count": len(remediated),
        "total_controls": len(checks_before),
    }


# ─────────────────────────────────────────────────────────────
# 2) Độ nhạy chính sách với KEV/EPSS (RQ5)
# ─────────────────────────────────────────────────────────────

# Bản sao đơn giản vế BLOCK của G2 cho phát hiện SCA (xem policy/g2/gate.rego).
def g2_sca_decision(severity, kev, epss, fix_available, confidence):
    if kev:
        return "BLOCK"
    if epss >= 0.10:
        return "BLOCK"
    if severity in {"CRITICAL", "HIGH"} and fix_available and confidence == "high":
        return "BLOCK"
    return "WARN"


# T0 is a deliberately synthetic scenario used only to demonstrate policy
# sensitivity. It is not a historical CISA/FIRST snapshot and must not be
# described as evidence about these CVEs' actual KEV/EPSS status.
SIMULATED_KEV_T0 = {"CVE-2024-35195"}
SIMULATED_EPSS_T0 = {"CVE-2023-45803": 0.124, "CVE-2024-35195": 0.05}

DRIFT_FINDINGS = [
    # severity MEDIUM isolates the simulated KEV/EPSS contribution.
    {"cve": "CVE-2024-35195", "severity": "MEDIUM", "fix_available": True},
    {"cve": "CVE-2023-45803", "severity": "MEDIUM", "fix_available": True},
    {"cve": "CVE-2024-24762", "severity": "HIGH", "fix_available": True},
]


def db_drift_analysis(kev_t1: set, epss_t1: dict) -> dict:
    changed = []
    rows = []
    for f in DRIFT_FINDINGS:
        cve = f["cve"]
        d0 = g2_sca_decision(
            f["severity"], cve in SIMULATED_KEV_T0, SIMULATED_EPSS_T0.get(cve, 0.0),
            f["fix_available"], "high",
        )
        d1 = g2_sca_decision(
            f["severity"], cve in kev_t1, epss_t1.get(cve, 0.0),
            f["fix_available"], "high",
        )
        rows.append({"cve": cve, "decision_T0": d0, "decision_T1": d1})
        if d0 != d1:
            changed.append({"cve": cve, "from": d0, "to": d1})
    return {
        "description": (
            "Mô phỏng chính sách với tín hiệu KEV/EPSS T0 được tạo có chủ đích; "
            "không phải snapshot lịch sử CISA/FIRST và không mô tả trạng thái thật của CVE."
        ),
        "rows": rows,
        "changed_decisions": changed,
        "changed_count": len(changed),
    }


# ─────────────────────────────────────────────────────────────
# 3) Chế độ live: build + scan + SBOM (khi có công cụ)
# ─────────────────────────────────────────────────────────────

def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def normalized_vulnerability_db(runtime: dict | None) -> dict | None:
    databases = (runtime or {}).get("databases") or {}
    entry = next(
        (value for name, value in databases.items()
         if "vulnerability" in name.casefold() and isinstance(value, dict)),
        None,
    )
    if not entry:
        return None
    identity = {
        key: entry.get(key)
        for key in ("version", "updated_at", "next_update")
        if entry.get(key) is not None
    }
    return identity if identity.get("updated_at") else None


def capture_trivy_runtime(out_dir: Path, label: str) -> dict | None:
    output = out_dir / f"trivy-runtime-{label}.json"
    recorder = PROJECT_DIR / "tests" / "record_trivy_runtime.py"
    captured = run([sys.executable, str(recorder), "--out", str(output)])
    if captured.returncode != 0 or not output.is_file():
        return None
    try:
        value = json.loads(output.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) and not value.get("error") else None


def live_comparison(before_dockerfile: Path, after_dockerfile: Path,
                    context: Path, out_dir: Path,
                    trivy_runtime_meta: Path | None = None) -> dict | None:
    if not all(shutil.which(t) for t in ("docker", "trivy", "syft")):
        return None

    out_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    observed_db_snapshots = []
    prior_runtime = {}
    try:
        if trivy_runtime_meta and trivy_runtime_meta.is_file():
            prior_runtime = json.loads(trivy_runtime_meta.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        prior_runtime = {}
    prior_db_snapshot = normalized_vulnerability_db(prior_runtime)
    for tag, dockerfile in (("before", before_dockerfile), ("after", after_dockerfile)):
        image = f"devsecops-e4-{tag}:lab"
        build = run(["docker", "build", "-f", str(dockerfile), "-t", image, str(context)])
        if build.returncode != 0:
            return {"error": f"docker build {tag} failed: {build.stderr[-500:]}"}

        runtime = run(["docker", "run", "--rm", "--entrypoint", "python", image, "--version"])
        if runtime.returncode != 0:
            return {"error": f"could not read Python runtime in {tag} image: {runtime.stderr[-500:]}"}
        python_version = runtime.stdout.strip().removeprefix("Python ")

        trivy_json = out_dir / f"trivy-image-{tag}.json"
        scan_args = ["trivy", "image", "--format", "json", "--output", str(trivy_json),
                     "--exit-code", "0"]
        if prior_db_snapshot:
            # The CI image job has already populated the database and recorded
            # its metadata. Do not let either E4 scan refresh it mid-comparison.
            scan_args.append("--skip-db-update")
        scan_args.append(image)
        runtime_before = capture_trivy_runtime(out_dir, f"{tag}-before-scan")
        scan = run(scan_args)
        if scan.returncode != 0 or not trivy_json.is_file():
            return {"error": f"Trivy scan {tag} failed: {scan.stderr[-500:]}"}
        runtime_after = capture_trivy_runtime(out_dir, f"{tag}-after-scan")
        db_before = normalized_vulnerability_db(runtime_before)
        db_after = normalized_vulnerability_db(runtime_after)
        observed_db_snapshots.extend((db_before, db_after))
        sbom_json = out_dir / f"sbom-{tag}.cdx.json"
        sbom = run(["syft", image, "-o", f"cyclonedx-json={sbom_json}"])
        if sbom.returncode != 0 or not sbom_json.is_file():
            return {"error": f"Syft SBOM {tag} failed: {sbom.stderr[-500:]}"}

        vulns = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        packages = 0
        image_metadata = {}
        sbom_metadata = {}
        if trivy_json.is_file():
            data = json.loads(trivy_json.read_text(encoding="utf-8"))
            metadata = data.get("Metadata") or {}
            image_config = metadata.get("ImageConfig") or {}
            image_metadata = {
                "image_id": metadata.get("ImageID"),
                "image_config_digest": metadata.get("ImageID"),
                "manifest_digest_available": bool(metadata.get("RepoDigests")),
                "repo_tags": metadata.get("RepoTags") or [],
                "repo_digests": metadata.get("RepoDigests") or [],
                "os": metadata.get("OS") or {},
                "architecture": image_config.get("architecture"),
                "python_version": python_version,
                "dockerfile": str(dockerfile),
                "dockerfile_sha256": hashlib.sha256(dockerfile.read_bytes()).hexdigest(),
                "dockerfile_base": next(
                    (line.strip() for line in dockerfile.read_text(encoding="utf-8").splitlines()
                     if line.strip().upper().startswith("FROM ")),
                    None,
                ),
            }
            for res in data.get("Results", []):
                for v in res.get("Vulnerabilities", []) or []:
                    sev = str(v.get("Severity", "UNKNOWN")).upper()
                    vulns[sev] = vulns.get(sev, 0) + 1
        if sbom_json.is_file():
            data = json.loads(sbom_json.read_text(encoding="utf-8"))
            packages = len(data.get("components", []))
            sbom_metadata = {
                "serial_number": data.get("serialNumber"),
                "timestamp": (data.get("metadata") or {}).get("timestamp"),
                "component": (data.get("metadata") or {}).get("component"),
            }

        result[tag] = {
            "vulnerabilities": vulns,
            "sbom_packages": packages,
            "image": image_metadata,
            "sbom": sbom_metadata,
            "trivy_database_before_scan": db_before,
            "trivy_database_after_scan": db_after,
        }

    if "before" in result and "after" in result:
        b, a = result["before"], result["after"]
        result["delta"] = {
            "vulnerabilities_total": (
                sum(a["vulnerabilities"].values()) - sum(b["vulnerabilities"].values())
            ),
            "sbom_packages": a["sbom_packages"] - b["sbom_packages"],
            "vulnerabilities_by_severity": {
                severity: a["vulnerabilities"].get(severity, 0)
                - b["vulnerabilities"].get(severity, 0)
                for severity in sorted(
                    set(b["vulnerabilities"]) | set(a["vulnerabilities"])
                )
            },
        }

        confounds = []
        for label, before_value, after_value in (
            ("Python version", b["image"].get("python_version"), a["image"].get("python_version")),
            ("OS release", b["image"].get("os"), a["image"].get("os")),
            ("architecture", b["image"].get("architecture"), a["image"].get("architecture")),
        ):
            if before_value != after_value:
                confounds.append({"dimension": label, "before": before_value, "after": after_value})

        try:
            runtime = (
                json.loads(trivy_runtime_meta.read_text(encoding="utf-8-sig"))
                if trivy_runtime_meta and trivy_runtime_meta.is_file()
                else {}
            )
        except (OSError, json.JSONDecodeError) as error:
            runtime = {"error": str(error)}

        result["provenance"] = {
            "ci_run_id": os.environ.get("GITHUB_RUN_ID"),
            "ci_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "ci_run_url": (
                f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com').rstrip('/')}"
                f"/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
                if os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID")
                else ""
            ),
            "commit": os.environ.get("GITHUB_SHA"),
            "fixture_id": os.environ.get("FIXTURE_ID", "baseline"),
            "tool_versions": {
                "trivy": os.environ.get("TRIVY_VERSION"),
                "syft": os.environ.get("SYFT_VERSION"),
            },
            "trivy_vulnerability_database": (runtime.get("databases") or {}).get("Vulnerability DB"),
        }
        observed_snapshots_complete = bool(observed_db_snapshots) and all(observed_db_snapshots)
        observed_snapshots_equal = (
            observed_snapshots_complete
            and all(snapshot == observed_db_snapshots[0] for snapshot in observed_db_snapshots)
        )
        prior_snapshot_matches = not prior_db_snapshot or (
            observed_snapshots_complete and prior_db_snapshot == observed_db_snapshots[0]
        )
        result["provenance"]["trivy_database_snapshots_per_scan"] = {
            "before_image_before_scan": b.get("trivy_database_before_scan"),
            "before_image_after_scan": b.get("trivy_database_after_scan"),
            "after_image_before_scan": a.get("trivy_database_before_scan"),
            "after_image_after_scan": a.get("trivy_database_after_scan"),
            "pre_e4_image_job_snapshot": prior_db_snapshot,
        }
        result["comparability"] = {
            "same_application_build_context": True,
            "same_python_version": bool(
                b["image"].get("python_version")
                and b["image"].get("python_version") == a["image"].get("python_version")
            ),
            "same_os_release": bool(
                b["image"].get("os")
                and b["image"].get("os") == a["image"].get("os")
            ),
            "same_architecture": bool(
                b["image"].get("architecture")
                and b["image"].get("architecture") == a["image"].get("architecture")
            ),
            "shared_trivy_database_snapshot": observed_snapshots_equal and prior_snapshot_matches,
            "confounds": confounds,
            "interpretation": (
                "The image digest identifies the local image configuration; the Dockerfile SHA-256 "
                "identifies each build recipe. Attribute the aggregate delta to the Dockerfile/image "
                "change as a whole only when all comparability checks pass."
            ),
        }
        comparable = result["comparability"]
        comparable["causal_attribution_allowed"] = all((
            comparable["same_application_build_context"],
            comparable["same_python_version"],
            comparable["same_os_release"],
            comparable["same_architecture"],
            comparable["shared_trivy_database_snapshot"],
        ))
        result["evidence_status"] = "comparable" if comparable["causal_attribution_allowed"] else "limited"
    return result


# ─────────────────────────────────────────────────────────────

def load_kev_epss(kev_path: Path, epss_path: Path):
    kev = json.loads(kev_path.read_text(encoding="utf-8"))
    kev_ids = {
        v["cveID"].upper() for v in kev.get("vulnerabilities", [])
    }
    epss = json.loads(epss_path.read_text(encoding="utf-8"))
    epss_map = {
        s["cve"].upper(): float(s["epss"]) for s in epss.get("scores", [])
    }
    return kev_ids, epss_map


def build_markdown(metrics: dict) -> str:
    s = metrics["structural"]
    lines = [
        "# E4 – Ảnh hưởng của khắc phục lên image và SBOM",
        "",
        "> **RQ5 / phân công Tài**: so sánh image trước và sau khi sửa;",
        "> đo độ nhạy quyết định khi tín hiệu KEV/EPSS thay đổi. T0 là mô phỏng,",
        "> không phải snapshot lịch sử có nguồn dẫn.",
        "",
        "## 1. Khắc phục cấu trúc Dockerfile",
        "",
        "| Chiều kiểm soát | Trước (Dockerfile.vuln) | Sau (Dockerfile) |",
        "|---|---|---|",
    ]
    label = {
        "non_root_user": "USER không root",
        "no_add_remote": "Không ADD từ URL",
        "no_sshd_or_port22": "Không sshd / cổng 22",
        "multi_stage": "Multi-stage (không base đầy đủ)",
    }
    for key in ("non_root_user", "no_add_remote", "no_sshd_or_port22", "multi_stage"):
        b = "ĐẠT" if s["before"][key] else "VI PHẠM"
        a = "ĐẠT" if s["after"][key] else "VI PHẠM"
        lines.append(f"| {label[key]} | {b} | {a} |")
    lines.append("")
    lines.append(
        f"Số chiều được khắc phục: **{s['remediated_count']}/{s['total_controls']}**"
    )
    lines.extend([
        "",
        "## 2. Độ nhạy chính sách với tín hiệu KEV/EPSS",
        "",
        metrics["db_drift"]["description"],
        "",
    ])
    lines.append("| CVE | Quyết định G2 tại T0 | Quyết định G2 tại T1 |")
    lines.append("|---|---|---|")
    for row in metrics["db_drift"]["rows"]:
        lines.append(
            f"| {row['cve']} | {row['decision_T0']} | {row['decision_T1']} |"
        )
    lines.append("")
    lines.append(
        f"Số quyết định thay đổi giữa tín hiệu T0 mô phỏng và tập T1 đã ghim: "
        f"**{metrics['db_drift']['changed_count']}**"
    )
    for ch in metrics["db_drift"]["changed_decisions"]:
        lines.append(f"- {ch['cve']}: {ch['from']} → {ch['to']}")
    lines.extend(["", "## 3. So sánh image/SBOM (chế độ live)", ""])
    live = metrics.get("live")
    if live and "error" not in live and "before" in live:
        lines.append("| Chỉ số | Trước | Sau | Delta |")
        lines.append("|---|---:|---:|---:|")
        b, a = live["before"], live["after"]
        lines.append(
            f"| Gói trong SBOM | {b['sbom_packages']} | {a['sbom_packages']} "
            f"| {live['delta']['sbom_packages']:+d} |"
        )
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            lines.append(
                f"| Lỗ hổng {sev} | {b['vulnerabilities'][sev]} "
                f"| {a['vulnerabilities'][sev]} "
                f"| {a['vulnerabilities'][sev] - b['vulnerabilities'][sev]:+d} |"
            )
        lines.append(
            f"| Tổng lỗ hổng | {sum(b['vulnerabilities'].values())} "
            f"| {sum(a['vulnerabilities'].values())} "
            f"| {live['delta']['vulnerabilities_total']:+d} |"
        )
        lines.extend(["", "### Nhận dạng image và tính so sánh", ""])
        for tag in ("before", "after"):
            image = live[tag].get("image", {})
            lines.append(
                f"- {tag}: image ID `{image.get('image_id') or 'không có'}`, "
                f"Python `{image.get('python_version') or 'không rõ'}`, "
                f"OS `{image.get('os') or 'không rõ'}`, "
                f"architecture `{image.get('architecture') or 'không rõ'}`."
            )
        comparable = live.get("comparability", {})
        if comparable:
            lines.append(
                f"- Trạng thái E4 live: **{live.get('evidence_status', 'limited')}**; "
                f"được phép quy kết delta cho thay đổi Dockerfile: "
                f"**{comparable.get('causal_attribution_allowed', False)}**."
            )
            lines.append(
                f"- Cùng phiên bản Python: **{comparable.get('same_python_version')}**; "
                f"cùng OS: **{comparable.get('same_os_release')}**; "
                f"cùng architecture: **{comparable.get('same_architecture')}**; "
                f"cùng Trivy DB snapshot đã xác minh theo từng lần quét: "
                f"**{comparable.get('shared_trivy_database_snapshot')}**; "
                f"snapshot mức job đã ghi: **{comparable.get('job_level_trivy_snapshot_recorded', 'không rõ')}**."
            )
            for confound in comparable.get("confounds", []):
                lines.append(
                    f"- Yếu tố khác nhau cần ghi nhận: {confound['dimension']} "
                    f"`{confound.get('before')}` → `{confound.get('after')}`."
                )
        provenance = live.get("provenance", {})
        db = provenance.get("trivy_vulnerability_database") or {}
        if provenance.get("ci_run_id"):
            lines.append(f"- CI run: `{provenance['ci_run_id']}`.")
        for tag in ("before", "after"):
            image = live[tag].get("image", {})
            lines.append(
                f"- `{tag}` config digest: `{image.get('image_config_digest') or 'không có'}`; "
                f"manifest digest trên registry: "
                f"`{', '.join(image.get('repo_digests') or []) or 'chưa có'}`; "
                f"Dockerfile SHA-256: `{image.get('dockerfile_sha256') or 'không có'}`."
            )
        if db.get("updated_at"):
            lines.append(f"- Trivy vulnerability DB cập nhật: `{db['updated_at']}`.")
    elif live and "error" in live:
        lines.append(f"Chế độ live lỗi: `{live['error']}`")
    else:
        lines.append(
            "Chưa có số liệu live. Chạy `python tests/e4_image_remediation.py "
            "--live --out-dir reports/e4` trên runner có Docker, Trivy và Syft "
            "để tạo báo cáo trước/sau cùng hai SBOM."
        )
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="E4: image/SBOM remediation analysis")
    parser.add_argument("--before", default=str(PROJECT_DIR / "lab" / "docker" / "Dockerfile.vuln"))
    parser.add_argument("--after", default=str(PROJECT_DIR / "Dockerfile"))
    parser.add_argument("--context", default=str(PROJECT_DIR))
    parser.add_argument("--kev", default=str(PROJECT_DIR / "security" / "kev" / "cisa_kev_subset.json"))
    parser.add_argument("--epss", default=str(PROJECT_DIR / "security" / "kev" / "epss_subset.json"))
    parser.add_argument("--out-dir", default=str(PROJECT_DIR / "tests" / "results" / "metrics"))
    parser.add_argument(
        "--trivy-runtime-meta",
        type=Path,
        default=None,
        help="Optional JSON from record_trivy_runtime.py for the DB snapshot used by both scans.",
    )
    parser.add_argument("--live", action="store_true",
                        help="Buật thử build/scan live kể cả khi tự phát hiện thất bại")
    parser.add_argument(
        "--strict-comparability",
        action="store_true",
        help="Fail if live E4 data is absent or Python/OS/architecture/Trivy DB snapshots are not comparable.",
    )
    args = parser.parse_args()

    before = Path(args.before)
    after = Path(args.after)
    if not before.is_file() or not after.is_file():
        print(f"ERROR: thiếu Dockerfile so sánh: {before} / {after}", file=sys.stderr)
        return 1

    kev_ids, epss_map = load_kev_epss(Path(args.kev), Path(args.epss))

    metrics = {
        "experiment": "E4",
        "structural": structural_comparison(before, after),
        "db_drift": db_drift_analysis(kev_ids, epss_map),
        "live": live_comparison(before, after, Path(args.context),
                                Path(args.out_dir).parent / "raw" / "e4",
                                args.trivy_runtime_meta)
        if args.live or all(shutil.which(t) for t in ("docker", "trivy", "syft"))
        else None,
    }
    if metrics["live"] is None:
        metrics["evidence_status"] = "not-measured-live"
        metrics["causal_attribution_allowed"] = False
    elif "error" in metrics["live"]:
        metrics["evidence_status"] = "failed-live"
        metrics["causal_attribution_allowed"] = False
    else:
        metrics["evidence_status"] = metrics["live"].get("evidence_status", "limited")
        metrics["causal_attribution_allowed"] = bool(
            metrics["live"].get("comparability", {}).get("causal_attribution_allowed")
        )
    live_failed = (args.live or args.strict_comparability) and (
        metrics["live"] is None or "error" in metrics["live"]
    )
    if args.strict_comparability and metrics["live"] and "error" not in metrics["live"]:
        live_failed = not metrics["live"].get("comparability", {}).get("causal_attribution_allowed", False)

    print("=" * 65)
    print("E4 – KHẮC PHỤC IMAGE / SBOM")
    print("=" * 65)
    s = metrics["structural"]
    print(f"Chiều khắc phục: {s['remediated_count']}/{s['total_controls']} "
          f"({', '.join(s['remediated_controls']) or 'không có'})")
    d = metrics["db_drift"]
    print(f"Quyết định đổi giữa T0 mô phỏng và T1 đã ghim: {d['changed_count']}")
    for ch in d["changed_decisions"]:
        print(f"  - {ch['cve']}: {ch['from']} -> {ch['to']}")
    if metrics["live"]:
        if "error" in metrics["live"]:
            print(f"Live: lỗi {metrics['live']['error'][:200]}")
        else:
            print(f"Live: delta lỗ hổng {metrics['live']['delta']['vulnerabilities_total']:+d}, "
                  f"delta gói SBOM {metrics['live']['delta']['sbom_packages']:+d}")
            print(f"So sánh: {metrics['live'].get('evidence_status', 'limited')}")
    else:
        print("Live: bỏ qua (thiếu docker/trivy/syft trên máy này)")
    print("=" * 65)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / "e4_image_remediation.json"
    json_out.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    md_out = out_dir / "e4_image_remediation.md"
    md_out.write_text(build_markdown(metrics) + "\n", encoding="utf-8")
    print(f"\nKết quả lưu tại: {json_out}")
    print(f"Báo cáo Markdown: {md_out}")
    return 1 if live_failed else 0


if __name__ == "__main__":
    sys.exit(main())
