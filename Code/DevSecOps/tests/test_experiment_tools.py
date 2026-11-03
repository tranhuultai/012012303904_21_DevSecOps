import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "tools" / "test"))
sys.path.insert(0, str(PROJECT_DIR / "tools"))
sys.path.insert(0, str(PROJECT_DIR / "tests"))

import collect_experiment as ce  # noqa: E402
import e4_summarize as e4s  # noqa: E402
import fetch_kev_epss as fke  # noqa: E402
import normalize_findings as nf  # noqa: E402


def run_py(script, *args):
    env = {**os.environ, "PYTHONUTF8": "1"}
    return subprocess.run([sys.executable, str(script), *map(str, args)],
                          capture_output=True, encoding="utf-8", env=env)


def finding(tool, rule_id, file, resource="", line=1, category="iac", severity="HIGH"):
    return nf.make_finding(tool=tool, rule_id=rule_id, category=category, severity=severity,
                           title=rule_id, message="", file=file, resource=resource, line_start=line)


# ---- normalize_findings: luật Conftest, bảng mức độ, tham số mới ----
def test_parse_conftest_rule_ids_and_severity():
    report = [{"filename": "lab/ci.yml", "failures": [
        {"msg": "GHA-WRITE-ALL: workflow-level permissions write-all"},
        {"msg": "GHA-UNPINNED-ACTION: mutable action reference actions/checkout@v7 in job build"},
    ]}]
    by_rule = {f["rule_id"]: f for f in nf.parse_conftest(report)}
    assert by_rule["GHA-WRITE-ALL"]["severity"] == "HIGH"
    assert by_rule["GHA-UNPINNED-ACTION"]["severity"] == "MEDIUM"
    assert by_rule["GHA-WRITE-ALL"]["category"] == "workflow"
    assert by_rule["GHA-WRITE-ALL"]["tool"] == "conftest"


def test_checkov_without_severity_uses_map_default():
    report = {"results": {"failed_checks": [
        {"check_id": "CKV_AWS_18", "check_name": "logging", "file_path": "/infra/s3.tf",
         "resource": "aws_s3_bucket.app", "check_result": {"result": "FAILED"}},
    ]}}
    assert nf.parse_checkov(report)[0]["severity"] == "MEDIUM"


def test_semgrep_registry_and_trivy_image_labels():
    sem = {"results": [{"check_id": "python.x", "path": "src/app/main.py",
                        "start": {"line": 3}, "extra": {"severity": "ERROR"}}]}
    assert nf.parse_semgrep(sem, tool="semgrep-registry")[0]["tool"] == "semgrep-registry"
    trivy = {"Results": [{"Target": "img (debian 13)", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-0001", "PkgName": "libx", "Severity": "HIGH"}]}]}
    assert nf.parse_trivy(trivy, category="image")[0]["category"] == "image"


# ---- collect_experiment: fingerprint ổn định, đánh dấu baseline ----
def test_stable_fingerprint_ignores_line():
    a = finding("checkov", "CKV_AWS_24", "infra/sg.tf", "aws_security_group.x", line=5)
    b = finding("checkov", "CKV_AWS_24", "infra/sg.tf", "aws_security_group.x", line=40)
    assert ce.stable_fingerprint(a) == ce.stable_fingerprint(b)


def write_sample(root, change_id, findings):
    d = root / f"exp-{change_id}"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"kind": "scan", "change_id": change_id, "commit": "abc",
                                             "run_id": "1", "run_url": "u"}), encoding="utf-8")
    (d / "normalized_findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (d / "timings.tsv").write_text("step\tstarted\tfinished\texit_code\ntrivy_fs\t1.0\t3.5\t0\n",
                                   encoding="utf-8")
    (d / "versions.json").write_text(json.dumps({"semgrep": "1", "trivy": {
        "Version": "0.76.1", "VulnerabilityDB": {"UpdatedAt": "2026-11-03T00:00:00Z"}}}),
        encoding="utf-8")


def test_collect_marks_baseline_and_missing(tmp_path):
    base = finding("checkov", "CKV_AWS_18", "infra/s3.tf", "aws_s3_bucket.logs")
    new = finding("checkov", "CKV_AWS_24", "infra/sg.tf", "aws_security_group.alb")
    write_sample(tmp_path / "exp", "BASE", [base])
    write_sample(tmp_path / "exp", "D16", [base, new])
    out = tmp_path / "out"
    assert run_py(str(PROJECT_DIR / "tests" / "collect_experiment.py"),
                           "--input", str(tmp_path / "exp"), "--out", str(out)).returncode == 0
    rows = list(csv.DictReader((out / "findings_all.csv").open(encoding="utf-8")))
    d16 = {r["rule_id"]: r["in_baseline"] for r in rows if r["change_id"] == "D16"}
    assert d16 == {"CKV_AWS_18": "1", "CKV_AWS_24": "0"}
    status = {r["change_id"]: r["status"] for r in csv.DictReader((out / "samples.csv").open(encoding="utf-8"))}
    assert status["D16"] == "complete" and status["D01"] == "missing"
    timing = next(csv.DictReader((out / "scan_runs.csv").open(encoding="utf-8")))
    assert float(timing["seconds"]) == pytest.approx(2.5)


# ---- eval_policies: Conftest thật trên policy/g0..g2 ----
@pytest.mark.skipif(shutil.which("conftest") is None, reason="cần conftest trong PATH")
def test_eval_policies_full_vs_delta(tmp_path):
    base = finding("checkov", "CKV_AWS_18", "infra/s3.tf", "aws_s3_bucket.logs", severity="MEDIUM")
    new = finding("checkov", "CKV_AWS_24", "infra/sg.tf", "aws_security_group.alb")
    write_sample(tmp_path / "exp", "BASE", [base])
    write_sample(tmp_path / "exp", "D16", [base, new])
    write_sample(tmp_path / "exp", "C05", [base])
    (tmp_path / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (tmp_path / "epss.json").write_text('{"scores": []}', encoding="utf-8")
    out = tmp_path / "out"
    result = run_py(str(PROJECT_DIR / "tests" / "eval_policies.py"),
                             "--input", str(tmp_path / "exp"), "--kev", str(tmp_path / "kev.json"),
                             "--epss", str(tmp_path / "epss.json"), "--today", "2026-11-03",
                             "--out", str(out))
    assert result.returncode == 0, result.stderr
    rows = list(csv.DictReader((out / "decisions.csv").open(encoding="utf-8")))
    dec = {(r["change_id"], r["policy"], r["mode"]): r["decision"] for r in rows}
    assert dec[("D16", "g2", "delta")] == "BLOCK"
    assert dec[("C05", "g2", "delta")] == "PASS"
    assert dec[("C05", "g1", "full")] == "BLOCK"   # G1 full chặn cả nhiễu baseline
    assert dec[("C05", "g1", "delta")] == "PASS"
    assert all(d == "PASS" for (c, p, m), d in dec.items() if p == "g0")
    assert len(rows) == 3 * 3 * 2


# ---- e4_summarize: đếm CVE duy nhất theo mức, bản vá, KEV ----
def test_e4_summarize_counts(tmp_path):
    def trivy(vulns):
        return {"Results": [{"Vulnerabilities": vulns}]}
    (tmp_path / "trivy_vuln.json").write_text(json.dumps(trivy([
        {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "FixedVersion": "2"},
        {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "FixedVersion": ""},
        {"VulnerabilityID": "CVE-2", "Severity": "CRITICAL", "FixedVersion": ""},
        {"VulnerabilityID": "CVE-3", "Severity": "LOW"},
    ])), encoding="utf-8")
    (tmp_path / "trivy_fixed.json").write_text(json.dumps(trivy([
        {"VulnerabilityID": "CVE-3", "Severity": "LOW"}])), encoding="utf-8")
    for img, n in (("vuln", 3), ("fixed", 1)):
        (tmp_path / f"syft_{img}.json").write_text(json.dumps({"artifacts": [{}] * n}), encoding="utf-8")
        (tmp_path / f"grype_{img}.json").write_text(json.dumps({"matches": [{}] * n}), encoding="utf-8")
    (tmp_path / "builds.tsv").write_text("image\trep\tseconds\nvuln\t1\t10\nvuln\t2\t12\nfixed\t1\t5\n",
                                         encoding="utf-8")
    (tmp_path / "sizes.tsv").write_text("image\tbytes\nvuln\t1000000000\nfixed\t200000000\n", encoding="utf-8")
    vuln = e4s.summarize("vuln", "lab/docker/Dockerfile.vuln", tmp_path, {"CVE-2"})
    assert (vuln["unique_cves"], vuln["trivy_records"]) == (3, 4)
    assert (vuln["critical"], vuln["high"], vuln["low"]) == (1, 1, 1)
    assert vuln["crit_high_fixable"] == 1 and vuln["kev_cves"] == 1
    assert vuln["build_seconds_median"] == 11.0 and vuln["size_mb"] == 1000.0


# ---- fetch_kev_epss: phần xử lý không cần mạng ----
def test_kev_snapshot_and_cve_scan(tmp_path):
    snap = fke.kev_snapshot({"catalogVersion": "2026.10.30", "count": 1,
                             "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]},
                            "2026-11-03T00:00:00Z")
    assert snap["catalogVersion"] == "2026.10.30" and snap["vulnerabilities"][0]["cveID"] == "CVE-2021-44228"
    path = tmp_path / "f.json"
    path.write_text(json.dumps([{"rule_id": "CVE-2024-24762"}, {"rule_id": "CKV_AWS_24", "cve": None}]),
                    encoding="utf-8")
    assert fke.cves_in([path]) == ["CVE-2024-24762"]


# ---- delta_findings: chế độ delta của gate trong CI ----
def test_delta_findings_keeps_only_new(tmp_path):
    import delta_findings as dfx
    base = {"tool": "checkov", "rule_id": "CKV_AWS_18", "file": "infra/s3.tf", "resource": "aws_s3_bucket.logs", "line_start": 3}
    moved = dict(base, line_start=30)
    new = {"tool": "checkov", "rule_id": "CKV_AWS_24", "file": "infra/sg.tf", "resource": "aws_security_group.alb"}
    (tmp_path / "base.json").write_text(json.dumps([base]), encoding="utf-8")
    (tmp_path / "cur.json").write_text(json.dumps([moved, new]), encoding="utf-8")
    out = tmp_path / "delta.json"
    assert run_py(str(PROJECT_DIR / "tools" / "delta_findings.py"),
                           "--current", str(tmp_path / "cur.json"), "--baseline", str(tmp_path / "base.json"),
                           "--out", str(out)).returncode == 0
    assert [f["rule_id"] for f in json.loads(out.read_text(encoding="utf-8"))] == ["CKV_AWS_24"]
    assert dfx.stable_fingerprint(base) == dfx.stable_fingerprint(moved)


def test_gate_input_rejects_object_without_findings(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"items": []}', encoding="utf-8")
    exc = tmp_path / "exc.yaml"
    exc.write_text("[]\n", encoding="utf-8")
    result = run_py(str(PROJECT_DIR / "tools" / "gate_input.py"),
                             "--findings", str(bad), "--exceptions", str(exc), "--today", "2026-11-03",
                             "--policy", "g2", "--out", str(tmp_path / "gi.json"))
    assert result.returncode != 0
    assert not (tmp_path / "gi.json").exists()
