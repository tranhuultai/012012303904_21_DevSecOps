"""Regression tests for live observation aggregation and evidence labeling."""

import json
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent
sys.path.insert(0, str(TESTS_DIR))

import analyze_fixture_observations as fixtures  # noqa: E402
import analyze_e4_artifact as e4_artifact  # noqa: E402
import e1_detection_effectiveness as e1  # noqa: E402
import e4_image_remediation as e4  # noqa: E402
import record_scan_observation as observation  # noqa: E402
import run_fixture_matrix as matrix  # noqa: E402
import summarize_e3_live as e3  # noqa: E402


def test_ground_truth_declares_gate_action_for_every_fixture():
    ground_truth = fixtures.load_ground_truth(
        Path(__file__).parents[1] / "ground_truth" / "ground_truth.csv"
    )
    assert len(ground_truth) == 46
    assert all(
        row.get(f"expected_{policy}") in {"PASS", "WARN", "BLOCK"}
        for row in ground_truth.values()
        for policy in fixtures.POLICIES
    )
    assert ground_truth["D10"]["expected_g2"] == "BLOCK"
    assert ground_truth["D23"]["expected_g2"] == "BLOCK"
    assert ground_truth["D20"]["expected_g2"] == "WARN"


def test_static_policy_decisions_are_not_labeled_as_live_scanner_metrics():
    metrics = e1.compute_metrics(
        {"D01": {"severity": "CRITICAL"}},
        {"C01"},
        {},
        "g2",
        {"g2": {"D01": "BLOCK", "C01": "PASS"}},
    )
    assert metrics["evidence_status"] == "exploratory-policy-replay"
    assert metrics["empirical_scanner_metric"] is False


def test_e3_stats_report_median_and_iqr():
    result = e3.stats([100, 110, 120, 130, 140])
    assert result == {
        "N": 5,
        "median": 120.0,
        "q1": 110.0,
        "q3": 130.0,
        "iqr": 20.0,
        "p90": 136.0,
    }


def test_e3_excludes_warmups_and_incomplete_observations(tmp_path):
    warmup = {
        "key": "e3-warmup",
        "fixture_id": "baseline",
        "cache_mode": "warm",
        "benchmark_role": "warmup",
        "conclusion": "success",
        "observation_status": "complete",
    }
    incomplete = {
        "key": "e3-incomplete",
        "fixture_id": "baseline",
        "cache_mode": "cold",
        "benchmark_role": "measurement",
        "conclusion": "success",
        "artifact_path": str(tmp_path / "incomplete"),
    }
    obs_dir = tmp_path / "incomplete"
    obs_dir.mkdir()
    (obs_dir / "observation.json").write_text(
        json.dumps({"fixture_id": "baseline", "evidence_status": "partial"}),
        encoding="utf-8",
    )
    report = e3.build_report({"runs": [warmup, incomplete]}, tmp_path / "run-index.json")
    assert report["profiles"]["cold"]["N"] == 0
    assert report["profiles"]["warm"]["N"] == 0
    assert len(report["excluded_runs"]) == 2
    assert report["evidence_status"] == "partial"


def test_e3_requires_five_runs_per_cache_with_one_commit_and_db_snapshot(tmp_path):
    runs = []
    for mode in ("cold", "warm"):
        for number in range(5):
            run_id = f"{mode}-{number}"
            obs_dir = tmp_path / run_id
            obs_dir.mkdir()
            observation = {
                "evidence_status": "complete",
                "fixture_id": "baseline",
                "commit": "abc123",
                "cache_mode": mode,
                "benchmark_role": "measurement",
                "tool_versions_configured": {"trivy": "0.76.1"},
                "trivy_db_snapshot_id": "20261115-v1",
                "grype_runtime": {
                    "grype_version": "0.120.1",
                    "db_snapshot_id": "20261115-v1",
                    "image_scan_skipped": False,
                    "db": {
                        "schema_version": "6.1.3",
                        "built": "2026-11-01T00:00:00Z",
                        "from": "2026-10-30T00:00:00Z",
                        "valid": True,
                    },
                },
                "trivy_runtime": {
                    "security-scan": {
                        "databases": {"Vulnerability DB": {"updated_at": "2026-11-01T00:00:00Z"}}
                    }
                },
            }
            (obs_dir / "observation.json").write_text(json.dumps(observation), encoding="utf-8")
            runs.append({
                "key": f"e3-{mode}-{number}",
                "run_id": run_id,
                "fixture_id": "baseline",
                "cache_mode": mode,
                "benchmark_role": "measurement",
                "conclusion": "success",
                "head_sha": "abc123",
                "observation_status": "complete",
                "artifact_path": str(obs_dir),
                "workflow_wall_seconds": 90 + number,
                "workflow_runner_minutes": 2.0,
                "scan_stage_wall_seconds": 60 + number,
                "scan_stage_runner_minutes": 1.0,
                "job_durations_seconds": {
                    "Run Python tests": 18,
                    "Prepare Trivy and Grype vulnerability DB snapshots": 8,
                    "Security scans (collection mode)": 20,
                    "iac": 25,
                    "image": 60,
                    "gate (Conftest Rego)": 12,
                },
                "job_conclusions": {
                    "Run Python tests": "success",
                    "Prepare Trivy and Grype vulnerability DB snapshots": "success",
                    "Security scans (collection mode)": "success",
                    "iac": "success",
                    "image": "success",
                    "gate (Conftest Rego)": "success",
                },
            })
    report = e3.build_report({"runs": runs}, tmp_path / "run-index.json")
    assert report["evidence_status"] == "complete"
    assert report["acceptance"]["same_commit"] is True
    assert report["acceptance"]["trivy_database_snapshot_consistent"] is True
    assert report["acceptance"]["trivy_database_snapshot_id_consistent"] is True
    assert report["acceptance"]["grype_database_snapshot_consistent"] is True
    assert report["acceptance"]["grype_database_snapshot_id_consistent"] is True

    for run in runs:
        run["conclusion"] = "failure"
        run["job_conclusions"]["gate (Conftest Rego)"] = "failure"
        observation_path = Path(run["artifact_path"]) / "observation.json"
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        observation["gate"] = {"decision": "BLOCK"}
        observation_path.write_text(json.dumps(observation), encoding="utf-8")
    report = e3.build_report({"runs": runs}, tmp_path / "run-index.json")
    assert report["evidence_status"] == "complete"
    assert report["profiles"]["cold"]["expected_baseline_gate_block_runs"] == 5
    assert report["profiles"]["warm"]["expected_baseline_gate_block_runs"] == 5

    runs[0]["job_conclusions"]["image"] = "failure"
    report = e3.build_report({"runs": runs}, tmp_path / "run-index.json")
    assert report["evidence_status"] == "partial"
    assert any("scanner job did not succeed" in item["reason"] for item in report["excluded_runs"])

    runs[-1]["head_sha"] = "different-commit"
    observation = json.loads((tmp_path / "warm-4" / "observation.json").read_text(encoding="utf-8"))
    observation["commit"] = "different-commit"
    (tmp_path / "warm-4" / "observation.json").write_text(json.dumps(observation), encoding="utf-8")
    report = e3.build_report({"runs": runs}, tmp_path / "run-index.json")
    assert report["evidence_status"] == "partial"
    assert report["acceptance"]["same_commit"] is False


def test_fixture_comparison_requires_target_rule_and_file():
    assert fixtures.path_matches("Code/DevSecOps/src/app/main.py", "src/app/main.py")
    assert fixtures.path_matches("/security_groups.tf", "infra/security_groups.tf")
    assert fixtures.finding_matches_rule(
        {"rule_id": "semgrep.sql-injection", "resource": ""},
        ["sql-injection"],
    )
    assert not fixtures.finding_matches_rule(
        {"rule_id": "semgrep.other", "resource": ""},
        ["sql-injection"],
    )


def test_checkov_identity_ignores_line_fingerprint_but_keeps_rule_resource_and_file():
    original = {
        "tool": "checkov",
        "rule_id": "CKV_AWS_24",
        "resource": "aws_security_group.app",
        "file": "/security_groups.tf",
        "fingerprint": "line-10",
    }
    shifted = {**original, "fingerprint": "line-14"}
    assert fixtures.finding_identity(original) == fixtures.finding_identity(shifted)
    assert fixtures.finding_identity(original) != fixtures.finding_identity(
        {**shifted, "resource": "aws_security_group.other"}
    )


def test_sca_match_uses_cve_when_trivy_reports_installed_metadata_path():
    expected = {
        "category": "sca",
        "expected_tool": "trivy",
        "file": "src/requirements.txt",
        "rule_or_cve": "CVE-2024-35195",
    }
    finding = {
        "tool": "trivy",
        "rule_id": "CVE-2024-35195",
        "file": "/opt/venv/lib/python3.13/site-packages/requests-2.31.0.dist-info/METADATA",
    }
    assert fixtures.finding_matches_defect(finding, expected)
    assert not fixtures.finding_matches_defect(
        {**finding, "rule_id": "CVE-2025-00001"}, expected
    )


def test_policy_confusion_and_warning_delta_respect_expected_warn_action():
    assert fixtures.policy_confusion_bucket("WARN", False) == "TN"
    assert fixtures.policy_confusion_bucket("WARN", True) == "FP"
    assert fixtures.policy_confusion_bucket("BLOCK", True) == "TP"
    baseline = {"policy_runs": [{
        "policy": "g2",
        "warnings": [{
            "rule_id": "warn",
            "message": "WARN IaC controls require review",
            "control_ids": ["CKV_AWS_21"],
            "advisory_ids": [],
            "affected_findings": [{"tool": "checkov", "category": "iac", "title": "CKV_AWS_21", "resource": "aws_s3_bucket.logs"}],
        }],
    }]}
    changed = {"policy_runs": [{
        "policy": "g2",
        "warnings": [{
            "rule_id": "warn",
            "message": "WARN IaC controls require review",
            "control_ids": ["CKV_AWS_21", "CKV_K8S_11"],
            "advisory_ids": [],
            "affected_findings": [{"tool": "checkov", "category": "iac", "title": "CKV_AWS_21", "resource": "aws_s3_bucket.logs"}],
        }],
    }]}
    assert len(fixtures.new_warnings_for_policy(changed, baseline, "g2")) == 1
    changed_same_controls = {"policy_runs": [{
        "policy": "g2",
        "warnings": [{
            "rule_id": "warn",
            "message": "WARN IaC controls require review",
            "control_ids": ["CKV_AWS_21"],
            "advisory_ids": [],
            "affected_findings": [
                {"tool": "checkov", "category": "iac", "title": "CKV_AWS_21", "resource": "aws_s3_bucket.logs"},
                {"tool": "checkov", "category": "iac", "title": "CKV_AWS_21", "resource": "aws_s3_bucket.app"},
            ],
        }],
    }]}
    assert len(fixtures.new_warnings_for_policy(changed_same_controls, baseline, "g2")) == 1


def test_run_matrix_timing_counts_wall_and_runner_time_separately():
    details = {
        "jobs": [
            {"name": "Security scans (collection mode)", "startedAt": "2026-01-01T00:00:00Z", "completedAt": "2026-01-01T00:00:20Z"},
            {"name": "iac", "startedAt": "2026-01-01T00:00:02Z", "completedAt": "2026-01-01T00:00:22Z"},
            {"name": "image", "startedAt": "2026-01-01T00:00:01Z", "completedAt": "2026-01-01T00:01:01Z"},
            {"name": "gate (Conftest Rego)", "startedAt": "2026-01-01T00:01:02Z", "completedAt": "2026-01-01T00:01:20Z"},
        ]
    }
    result = matrix.job_timing(details)
    assert result["scan_stage_wall_seconds"] == 61.0
    assert result["scan_stage_runner_minutes"] == 1.667
    assert result["workflow_wall_seconds"] == 80.0
    assert result["workflow_runner_minutes"] == 1.967


def test_run_matrix_ignores_old_runs_with_the_same_display_title():
    run = {
        "databaseId": 99,
        "event": "workflow_dispatch",
        "headSha": "abc123",
        "displayTitle": "DevSecOps CI | baseline | cold | measurement | abc123 | study001",
    }
    assert matrix.matching_runs(
        [run], "baseline", "cold", "measurement", "abc123", "study001",
        known_run_ids={99},
    ) == []
    assert matrix.matching_runs(
        [run], "baseline", "cold", "measurement", "abc123", "study001",
    ) == [run]


def test_run_matrix_requests_created_at_before_selecting_latest_run(monkeypatch):
    suffix = "| baseline | cold | measurement | abc123 | study001"
    runs = [
        {
            "databaseId": 100,
            "event": "workflow_dispatch",
            "headSha": "abc123",
            "displayTitle": f"DevSecOps CI {suffix}",
            "createdAt": "2026-01-01T00:00:00Z",
        },
        {
            "databaseId": 101,
            "event": "workflow_dispatch",
            "headSha": "abc123",
            "displayTitle": f"DevSecOps CI {suffix}",
            "createdAt": "2026-01-02T00:00:00Z",
        },
    ]
    requested = {}

    def fake_gh_json(args):
        requested["args"] = args
        return runs

    monkeypatch.setattr(matrix, "gh_json", fake_gh_json)
    latest = matrix.list_matching_run(
        "owner/repo", "main", "baseline", "cold", "measurement",
        "abc123", "study001",
    )

    assert latest["databaseId"] == 101
    json_fields = requested["args"][requested["args"].index("--json") + 1].split(",")
    assert "createdAt" in json_fields


def test_run_matrix_normalizes_baseline_and_fixture_ids():
    assert matrix.normalize_fixture_id("baseline") == "baseline"
    assert matrix.normalize_fixture_id("BASELINE") == "baseline"
    assert matrix.normalize_fixture_id("d04") == "D04"


def test_e4_database_snapshot_must_be_present_and_normalized():
    valid = {
        "databases": {
            "Vulnerability DB": {
                "version": "2",
                "updated_at": "2026-11-01T00:00:00Z",
                "next_update": "2026-11-02T00:00:00Z",
            }
        }
    }
    assert e4.normalized_vulnerability_db(valid) == {
        "version": "2",
        "updated_at": "2026-11-01T00:00:00Z",
        "next_update": "2026-11-02T00:00:00Z",
    }
    assert e4.normalized_vulnerability_db({"databases": {}}) is None


def test_e4_artifact_ingestion_checks_raw_totals_and_limits_causal_claim(tmp_path):
    def write_json(relative, value):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    for side, image_id, python_version, severity in (
        ("before", "sha256:before", "3.12.15", "HIGH"),
        ("after", "sha256:after", "3.12.15", "LOW"),
    ):
        write_json(f"raw/e4/trivy-image-{side}.json", {
            "Metadata": {
                "ImageID": image_id,
                "RepoTags": [f"image-{side}:test"],
                "RepoDigests": [],
                "OS": {"Family": "debian", "Name": "13.7"},
                "ImageConfig": {
                    "architecture": "amd64",
                    "config": {"Env": [f"PYTHON_VERSION={python_version}"]},
                },
            },
            "Results": [{"Vulnerabilities": [{"Severity": severity}]}],
        })
        write_json(f"raw/e4/sbom-{side}.cdx.json", {
            "serialNumber": f"urn:{side}",
            "metadata": {"timestamp": "2026-11-01T00:00:00Z"},
            "components": [{"name": "example"}],
        })

    db_snapshot = {
        "version": "2",
        "updated_at": "2026-11-01T00:00:00Z",
        "next_update": "2026-11-02T00:00:00Z",
    }
    write_json("experiment/trivy-runtime-image.json", {
        "trivy_version": "0.76.1",
        "databases": {"Vulnerability DB": db_snapshot},
        "error": None,
    })
    for name in (
        "before-before-scan", "before-after-scan",
        "after-before-scan", "after-after-scan",
    ):
        write_json(f"raw/e4/trivy-runtime-{name}.json", {
            "trivy_version": "0.76.1",
            "databases": {"Vulnerability DB": db_snapshot},
            "error": None,
        })
    write_json("timing/image.json", {
        "run_id": "123",
        "run_attempt": "1",
        "run_url": "https://github.com/example/project/actions/runs/123",
        "commit": "abc123",
        "fixture_id": "baseline",
    })
    write_json("e4/e4_image_remediation.json", {
        "experiment": "E4",
        "structural": {
            "before": {"non_root_user": False, "no_add_remote": False, "no_sshd_or_port22": False, "multi_stage": False},
            "after": {"non_root_user": True, "no_add_remote": True, "no_sshd_or_port22": True, "multi_stage": True},
            "remediated_count": 4,
            "total_controls": 4,
        },
        "db_drift": {"description": "simulated", "rows": [], "changed_count": 0, "changed_decisions": []},
        "live": {
            "before": {
                "vulnerabilities": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
                "sbom_packages": 1,
                "image": {"dockerfile_sha256": "before-dockerfile-hash"},
            },
            "after": {
                "vulnerabilities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0},
                "sbom_packages": 1,
                "image": {"dockerfile_sha256": "after-dockerfile-hash"},
            },
            "delta": {"vulnerabilities_total": 0, "sbom_packages": 0},
        },
    })

    result = e4_artifact.analyze(tmp_path)
    assert result["live"]["before"]["vulnerabilities_total"] == 1
    assert result["live"]["after"]["vulnerabilities_total"] == 1
    assert result["evidence_status"] == "comparable"
    assert result["causal_attribution_allowed"] is True
    assert result["live"]["comparability"]["same_python_version"] is True
    assert result["live"]["comparability"]["job_level_trivy_snapshot_recorded"] is True
    assert result["live"]["comparability"]["per_scan_trivy_snapshot_verified"] is True
    assert result["live"]["raw_artifact_sha256"]["trivy_before"]
    assert result["live"]["before"]["image"]["dockerfile_sha256"] == "before-dockerfile-hash"

    drift_path = tmp_path / "raw/e4/trivy-runtime-after-after-scan.json"
    drift = json.loads(drift_path.read_text(encoding="utf-8"))
    drift["databases"]["Vulnerability DB"]["updated_at"] = "2026-11-02T00:00:00Z"
    drift_path.write_text(json.dumps(drift), encoding="utf-8")
    result = e4_artifact.analyze(tmp_path)
    assert result["evidence_status"] == "limited"
    assert result["causal_attribution_allowed"] is False
    assert result["live"]["comparability"]["per_scan_trivy_snapshot_verified"] is False


def test_e1_e3_observation_does_not_require_optional_e4_artifacts(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    experiment = reports / "experiment"
    experiment.mkdir(parents=True)
    for name in observation.RAW_REPORTS:
        path = reports / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]\n", encoding="utf-8")
    (reports / "grype-image.json").write_text(json.dumps({
        "descriptor": {
            "version": "0.120.1",
            "db": {"status": {
                "schemaVersion": "v6.1.10",
                "built": "2026-11-01T00:00:00Z",
                "from": "https://example.invalid/grype-db.tar.zst",
                "valid": True,
            }},
        },
        "matches": [],
    }), encoding="utf-8")
    (reports / "normalized_findings.json").write_text("[]\n", encoding="utf-8")
    (experiment / "trivy-runtime-security-scan.json").write_text(
        json.dumps({
            "trivy_version": "0.76.1",
            "databases": {"Vulnerability DB": {"updated_at": "2026-11-01T00:00:00Z"}},
            "error": None,
        }),
        encoding="utf-8",
    )
    for policy in ("g0", "g1", "g2"):
        (experiment / f"gate-report-{policy}.json").write_text(
            json.dumps({
                "decision": "PASS" if policy == "g0" else "WARN",
                "summary": {"blockers": 0, "warnings": 1},
                "blockers": [],
                "warnings": [{
                    "rule_id": "warn",
                    "message": "WARN MEDIUM có bản vá: CVE-2024-35195",
                    "file": "gate_input.json",
                    "severity": "MEDIUM",
                    "advisory_ids": ["CVE-2024-35195"],
                    "control_ids": [],
                    "affected_findings": [{
                        "tool": "trivy", "category": "sca", "title": "CVE-2024-35195",
                        "file": "src/requirements.txt", "resource": "requests",
                        "package": "requests", "installed_version": "2.31.0",
                    }],
                }],
            }),
            encoding="utf-8",
        )
    gate = tmp_path / "gate.json"
    gate.write_text(json.dumps({"decision": "PASS", "policy_profile": "g2", "summary": {}}), encoding="utf-8")
    timing = tmp_path / "timing.json"
    timing.write_text(json.dumps({
        "fixture_id": "baseline",
        "run_id": "123",
        "run_attempt": "1",
        "commit": "abc123",
        "cache_mode": "cold",
        "benchmark_role": "measurement",
        "scan_execution_mode": "parallel",
        "scan_stage_started_at": "2026-11-01T00:00:00Z",
        "scan_stage_ended_at": "2026-11-01T00:01:00Z",
    }), encoding="utf-8")
    out = experiment / "observation.json"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/project")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("TRIVY_VERSION", "0.76.1")
    monkeypatch.setenv("GRYPE_VERSION", "0.120.1")
    monkeypatch.setenv("FIXTURE_ID", "baseline")
    monkeypatch.setenv("RUN_E4", "false")
    monkeypatch.setenv("CACHE_MODE", "cold")
    monkeypatch.setenv("BENCHMARK_ROLE", "measurement")
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "parallel")
    monkeypatch.setenv("CONTEST_POLICY", "g2")
    monkeypatch.setenv("TRIVY_DB_SNAPSHOT_ID", "20261115-v1")
    monkeypatch.setenv("GRYPE_DB_SNAPSHOT_ID", "20261115-v1")
    monkeypatch.setattr(sys, "argv", [
        "record_scan_observation.py",
        "--reports-dir", str(reports),
        "--gate-report", str(gate),
        "--timing-summary", str(timing),
        "--out", str(out),
    ])

    assert observation.main() == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["evidence_status"] == "complete"
    assert result["schema_version"] == 6
    assert result["trivy_db_snapshot_id"] == "20261115-v1"
    assert result["policy_runs"][2]["warnings"][0]["advisory_ids"] == ["CVE-2024-35195"]
    assert result["policy_runs"][2]["warnings"][0]["affected_findings"][0]["resource"] == "requests"
    assert result["e4_evidence_status"] == "not_requested"
    assert result["e4_requested"] is False
    assert all(not value["present"] for value in result["e4_raw_reports"].values())
    assert result["grype_runtime"]["grype_version"] == "0.120.1"
    assert result["grype_runtime"]["db_snapshot_id"] == "20261115-v1"
    assert result["grype_runtime"]["db"]["built"] == "2026-11-01T00:00:00Z"
    assert result["issues"] == []
