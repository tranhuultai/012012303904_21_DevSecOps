package main

import rego.v1

ctx := {"today": "2026-10-24", "policy": "g2"}

base(findings) := {"context": ctx, "findings": findings, "exceptions": []}

with_exc(findings, excs) := {"context": ctx, "findings": findings, "exceptions": excs}

test_g2_block_secret if {
	count(deny) > 0 with input as base([{"category": "secret", "rule_id": "gitleaks-aws", "severity": "HIGH", "location": {"file": "config.py"}}])
}

test_g2_block_kev_any_severity if {
	count(deny) > 0 with input as base([{"category": "sca", "rule_id": "CVE-x", "severity": "LOW", "kev": true, "location": {"file": "req"}}])
}

test_g2_block_sca_fixable_highconf if {
	count(deny) > 0 with input as base([{"category": "sca", "rule_id": "CVE-2020-14343", "severity": "HIGH", "fix_available": true, "match_confidence": "high", "kev": false, "location": {"file": "req"}}])
}

test_g2_warn_not_block_sca_nofix if {
	inp := base([{"category": "sca", "rule_id": "CVE-y", "severity": "HIGH", "fix_available": false, "match_confidence": "high", "kev": false, "location": {"file": "req"}}])
	count(deny) == 0 with input as inp
	count(warn) > 0 with input as inp
}

test_g2_block_iac_ssh_world if {
	count(deny) > 0 with input as base([{"category": "iac", "rule_id": "CKV_AWS_24", "severity": "HIGH", "location": {"resource": "aws_security_group.x"}}])
}

test_g2_warn_tier_iac_logging_not_block if {
	count(deny) == 0 with input as base([{"category": "iac", "rule_id": "CKV_AWS_18", "severity": "LOW", "location": {"resource": "aws_s3_bucket.x"}}])
}

test_g2_block_k8s_privileged if {
	count(deny) > 0 with input as base([{"category": "iac", "rule_id": "CKV_K8S_16", "severity": "HIGH", "location": {"resource": "Deployment.x"}}])
}

test_g2_block_trivy_cluster_admin if {
	count(deny) > 0 with input as base([{"category": "iac", "rule_id": "KSV-0111", "severity": "MEDIUM", "location": {"resource": "ClusterRoleBinding.x"}}])
}

test_g2_block_sast_high if {
	count(deny) > 0 with input as base([{"category": "sast", "rule_id": "python.sqli", "severity": "HIGH", "location": {"file": "main.py"}}])
}

test_g2_sast_low_not_block if {
	count(deny) == 0 with input as base([{"category": "sast", "rule_id": "python.weak-hash", "severity": "LOW", "location": {"file": "main.py"}}])
}

test_g2_clean_passes if {
	count(deny) == 0 with input as base([{"category": "iac", "rule_id": "CKV_DOCKER_3", "severity": "LOW", "location": {"file": "Dockerfile"}}])
}

test_g2_valid_exception_excuses if {
	excs := [{"id": "EXC-001", "match": {"rule_id": "CKV_AWS_24", "resource": "aws_security_group.alb_public"}, "severity": "HIGH", "reason": "ALB cong khai 443", "owner": "@tranhuultai", "approved_by": "@gialong611", "created": "2026-10-20", "expires": "2026-11-10"}]
	finds := [{"category": "iac", "rule_id": "CKV_AWS_24", "severity": "HIGH", "location": {"resource": "aws_security_group.alb_public"}}]
	count(deny) == 0 with input as with_exc(finds, excs)
}

test_g2_expired_exception_blocks if {
	excs := [{"id": "EXC-002", "match": {"rule_id": "CKV_AWS_24", "resource": "r"}, "severity": "HIGH", "reason": "r", "owner": "@a", "approved_by": "@b", "created": "2026-08-01", "expires": "2026-09-01"}]
	count(deny) > 0 with input as with_exc([], excs)
}

test_g2_owner_eq_approver_blocks if {
	excs := [{"id": "EXC-003", "match": {"rule_id": "X", "resource": "r"}, "severity": "HIGH", "reason": "r", "owner": "@a", "approved_by": "@a", "created": "2026-10-20", "expires": "2026-11-01"}]
	count(deny) > 0 with input as with_exc([], excs)
}

test_g2_exception_over_ceiling_not_excuse if {
	excs := [{"id": "EXC-005", "match": {"rule_id": "CKV_AWS_24", "resource": "r"}, "severity": "CRITICAL", "reason": "r", "owner": "@a", "approved_by": "@b", "created": "2026-10-01", "expires": "2026-10-30"}]
	finds := [{"category": "iac", "rule_id": "CKV_AWS_24", "severity": "HIGH", "location": {"resource": "r"}}]
	count(deny) > 0 with input as with_exc(finds, excs)
}

test_g2_secret_not_excusable if {
	excs := [{"id": "EXC-004", "match": {"rule_id": "gitleaks-aws", "resource": ""}, "severity": "HIGH", "reason": "r", "owner": "@a", "approved_by": "@b", "created": "2026-10-20", "expires": "2026-11-01"}]
	finds := [{"category": "secret", "rule_id": "gitleaks-aws", "severity": "HIGH", "location": {"file": "c.py"}}]
	count(deny) > 0 with input as with_exc(finds, excs)
}

test_g2_failclosed_missing_today if {
	count(deny) > 0 with input as {"context": {"policy": "g2"}, "findings": [], "exceptions": []}
}

test_g2_failclosed_missing_findings if {
	count(deny) > 0 with input as {"context": ctx, "exceptions": []}
}

test_g2_failclosed_finding_missing_severity if {
	count(deny) > 0 with input as base([{"category": "sast", "rule_id": "rule-no-sev"}])
}

test_g2_block_epss_high if {
	count(deny) > 0 with input as base([{"category": "sca", "rule_id": "CVE-epss-high", "severity": "LOW", "epss": 0.45, "location": {"file": "req"}}])
}

test_g2_warn_epss_medium if {
	inp := base([{"category": "sca", "rule_id": "CVE-epss-med", "severity": "LOW", "epss": 0.05, "location": {"file": "req"}}])
	count(deny) == 0 with input as inp
	count(warn) > 0 with input as inp
}
