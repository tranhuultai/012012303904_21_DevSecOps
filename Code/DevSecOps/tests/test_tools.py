#!/usr/bin/env python3
"""
Unit tests cho bộ công cụ chuẩn hóa / làm giàu / gate / E4.

Chạy: python -m pytest Code/DevSecOps/tests/test_tools.py -v
"""

import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
TOOLS_DIR = TESTS_DIR.parent / "tools"
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(TOOLS_DIR / "test"))

import normalize_findings as nf  # noqa: E402
import enrich_findings as ef  # noqa: E402
import conftest_gate_report as cgr  # noqa: E402
import e4_image_remediation as e4  # noqa: E402
from generate_pr_summary import build_summary  # noqa: E402


# ────────────────────────────────────────────────────────────
# normalize_findings: parser Checkov
# ────────────────────────────────────────────────────────────

CHECKOV_REPORT = {
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "SSH open to the world",
                "check_result": {"result": "FAILED"},
                "check_severity": "HIGH",
                "file_path": "infra/security_groups.tf",
                "file_line_range": [12, 20],
                "guideline": "https://example.com/CKV_AWS_24",
            },
            {
                "check_id": "CKV_K8S_16",
                "check_name": "Privileged container",
                "check_result": {"result": "FAILED"},
                "file_path": "deploy/deployment.yaml",
            },
            {
                "check_id": "CKV_DOCKER_3",
                "check_name": "Root user",
                "check_result": {"result": "FAILED"},
                "file_path": "Dockerfile",
            },
            {
                "check_id": "CKV_GHA_2",
                "check_name": "Script injection",
                "check_result": {"result": "FAILED"},
                "file_path": ".github/workflows/ci.yml",
            },
        ]
    }
}


def test_parse_checkov_categories_and_severity():
    findings = nf.parse_checkov(CHECKOV_REPORT)
    assert len(findings) == 4
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["CKV_AWS_24"]["category"] == "iac"
    assert by_rule["CKV_K8S_16"]["category"] == "k8s"
    assert by_rule["CKV_DOCKER_3"]["category"] == "image"
    assert by_rule["CKV_GHA_2"]["category"] == "workflow"
    assert by_rule["CKV_AWS_24"]["severity"] == "HIGH"
    # thiếu check_severity => FAILED => HIGH sau chuẩn hóa
    assert by_rule["CKV_K8S_16"]["severity"] == "HIGH"
    assert by_rule["CKV_AWS_24"]["tool"] == "checkov"
    assert by_rule["CKV_AWS_24"]["line_start"] == 12
    assert by_rule["CKV_AWS_24"]["line_end"] == 20


def test_parse_checkov_none_and_bad():
    assert nf.parse_checkov(None) == []
    with pytest.raises(ValueError):
        nf.parse_checkov({"results": {"failed_checks": "not-a-list"}})


# ────────────────────────────────────────────────────────────
# normalize_findings: parser Trivy config
# ────────────────────────────────────────────────────────────

TRIVY_CONFIG = {
    "Results": [
        {
            "Target": "deploy/deployment.yaml",
            "Misconfigurations": [
                {
                    "ID": "KSV-0109",
                    "Status": "FAILED",
                    "Severity": "HIGH",
                    "Title": "Secret in ConfigMap",
                    "References": ["https://avd.aquasec.com/ksv-0109"],
                },
                {
                    "ID": "KSV-0001",
                    "Status": "PASSED",
                    "Severity": "LOW",
                },
            ],
        }
    ]
}


def test_parse_trivy_config_only_failed():
    findings = nf.parse_trivy_config(TRIVY_CONFIG)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "KSV-0109"
    assert f["category"] == "k8s"
    assert f["severity"] == "HIGH"
    assert f["tool"] == "trivy"


def test_parse_trivy_config_none():
    assert nf.parse_trivy_config(None) == []


# ────────────────────────────────────────────────────────────
# normalize_findings: parser Grype
# ────────────────────────────────────────────────────────────

GRYPE_REPORT = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2023-45803",
                "severity": "High",
                "description": "urllib3 body leak",
                "fix": {"versions": ["2.0.7"]},
                "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"],
            },
            "artifact": {
                "name": "urllib3",
                "version": "2.0.6",
                "locations": [{"path": "/opt/venv/lib/urllib3"}],
            },
        }
    ]
}


def test_parse_grype():
    findings = nf.parse_grype(GRYPE_REPORT)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "grype"
    assert f["category"] == "image"
    assert f["cve"] == "CVE-2023-45803"
    assert f["severity"] == "HIGH"
    assert "Fixed version: 2.0.7" in f["message"]
    assert f["file"] == "/opt/venv/lib/urllib3"


def test_parse_grype_none():
    assert nf.parse_grype(None) == []


def test_checkov_finding_passes_schema(tmp_path):
    findings = nf.parse_checkov(CHECKOV_REPORT)
    schema_path = TESTS_DIR.parent / "schemas" / "finding.schema.json"
    nf.validate_findings(findings, schema_path)  # không raise là pass


# ────────────────────────────────────────────────────────────
# enrich_findings
# ────────────────────────────────────────────────────────────

KEV = {"vulnerabilities": [{"cveID": "CVE-2024-24762"}]}
EPSS = {"scores": [{"cve": "CVE-2024-24762", "epss": 0.156},
                   {"cve": "CVE-2023-45803", "epss": 0.05}]}


def test_enrich_kev_and_epss():
    findings = [
        {"rule_id": "CVE-2024-24762", "category": "sca", "severity": "HIGH",
         "file": "src/requirements.txt", "message": "Fixed version: 0.0.20"},
        {"rule_id": "CVE-2023-45803", "category": "sca", "severity": "HIGH",
         "file": "src/requirements.txt", "message": ""},
    ]
    kev_ids = ef.load_kev_ids(KEV)
    epss_map = ef.load_epss_map(EPSS)
    out = [ef.enrich(f, kev_ids, epss_map) for f in findings]
    assert out[0]["kev"] is True
    assert out[0]["epss"] == 0.156
    assert out[0]["fix_available"] is True
    assert out[0]["match_confidence"] == "high"
    assert out[1]["kev"] is False
    assert out[1]["epss"] == 0.05
    assert out[1]["fix_available"] is False
    assert out[0]["location"]["file"] == "src/requirements.txt"


def test_enrich_confidence_iac_control():
    kev_ids = set()
    epss_map = {}
    f = {"rule_id": "CKV_AWS_24", "category": "iac", "severity": "HIGH", "file": "a.tf"}
    out = ef.enrich(f, kev_ids, epss_map)
    assert out["match_confidence"] == "high"
    f2 = {"rule_id": "CKV_AWS_21", "category": "iac", "severity": "MEDIUM", "file": "a.tf"}
    assert ef.enrich(f2, kev_ids, epss_map)["match_confidence"] == "low"


# ────────────────────────────────────────────────────────────
# conftest_gate_report
# ────────────────────────────────────────────────────────────

def test_gate_report_block_on_deny():
    results = [{"failures": [{"msg": "G2 BLOCK secret"}], "filename": "gate_input.json"}]
    report = cgr.build_report(results, [], "g2")
    assert report["decision"] == "BLOCK"
    assert report["summary"]["blockers"] == 1


def test_gate_report_warn_only():
    results = [{"warnings": [{"msg": "WARN something"}], "filename": "gate_input.json"}]
    report = cgr.build_report(results, [], "g2")
    assert report["decision"] == "WARN"


def test_gate_report_pass():
    report = cgr.build_report([], [], "g2")
    assert report["decision"] == "PASS"


def test_gate_report_failclosed_unparsed():
    results = [{"failures": [{"no_msg_field": True}], "filename": None}]
    # extract_items sẽ tạo mục với title mặc định 'deny' -> vẫn BLOCK; kiểm tra
    report = cgr.build_report(results, [], "g2")
    assert report["decision"] == "BLOCK"


def test_pr_summary_from_gate_report():
    report = cgr.build_report(
        [{"failures": [{"msg": "deny"}], "filename": "x"}], [], "g2"
    )
    findings = [
        {"finding_id": "f1", "tool": "semgrep", "severity": "HIGH",
         "title": "SQLi", "status": "open"},
    ]
    md = build_summary(findings, report, title="T")
    assert "**Decision: BLOCK**" in md
    assert "| HIGH | 1 |" in md


# ────────────────────────────────────────────────────────────
# E4 helpers
# ────────────────────────────────────────────────────────────

def test_e4_dockerfile_checks_real_files():
    before = TESTS_DIR.parent / "lab" / "docker" / "Dockerfile.vuln"
    after = TESTS_DIR.parent / "Dockerfile"
    if not before.is_file() or not after.is_file():
        pytest.skip("thiếu Dockerfile so sánh")
    b = e4.dockerfile_checks(before)
    a = e4.dockerfile_checks(after)
    assert b["non_root_user"] is False
    assert b["no_add_remote"] is False
    assert b["no_sshd_or_port22"] is False
    assert b["multi_stage"] is False
    assert a["non_root_user"] is True
    assert a["no_add_remote"] is True
    assert a["no_sshd_or_port22"] is True
    assert a["multi_stage"] is True


def test_e4_g2_sca_decision_rules():
    assert e4.g2_sca_decision("LOW", True, 0.0, False, "low") == "BLOCK"  # KEV
    assert e4.g2_sca_decision("LOW", False, 0.2, False, "low") == "BLOCK"  # EPSS cao
    assert e4.g2_sca_decision("HIGH", False, 0.0, True, "high") == "BLOCK"
    assert e4.g2_sca_decision("HIGH", False, 0.0, False, "high") == "WARN"
    assert e4.g2_sca_decision("MEDIUM", False, 0.0, True, "high") == "WARN"


def test_e4_drift_with_current_kev():
    kev_ids = {"CVE-2024-24762", "CVE-2023-45803", "CVE-2022-42969"}
    epss = {"CVE-2024-24762": 0.156, "CVE-2023-45803": 0.182, "CVE-2022-42969": 0.124}
    drift = e4.db_drift_analysis(kev_ids, epss)
    changed = {c["cve"] for c in drift["changed_decisions"]}
    assert "CVE-2024-24762" in changed
