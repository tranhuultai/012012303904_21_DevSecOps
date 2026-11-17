# DevSecOps Security Summary (g2)

> Generated automatically on 2026-11-03 19:02 UTC.

## Gate result

**Decision: BLOCK**

The security gate found blocking issues. Review and remediate them before merging or deploying.

## Overview

| Metric | Count |
|---|---:|
| Total findings | 264 |
| Blockers | 1 |
| Warnings | 1 |
| Warnings linked to source findings | 0 |
| Active exceptions used | 0 |
| Expired exceptions | 0 |

## Findings by severity

| Severity | Count |
|---|---:|
| CRITICAL | 3 |
| HIGH | 65 |
| MEDIUM | 133 |
| LOW | 17 |
| INFO | 46 |

## Findings by tool

| Tool | Count |
|---|---:|
| semgrep | 0 |
| gitleaks | 0 |
| trivy | 17 |
| checkov | 65 |
| grype | 182 |

## Blocking findings

| Severity | Tool | Finding | Package / resource | Location | Policy / source IDs |
|---|---|---|---|---|---|
| CRITICAL | — | G2 BLOCK cấu hình: CKV_AWS_24 | — | `gate_input.json` | `deny:0` |

## Warning findings

| Severity | Tool | Finding | Package / resource | Location | Policy / source IDs |
|---|---|---|---|---|---|
| HIGH | conftest-rego | WARN HIGH (chưa đủ điều kiện chặn): AWS-0107 tại infra/security_groups.tf | — | `gate_input.json` | `warn:0` |

## Exception review

- Expired exceptions: **0**
- Unused exceptions: **0**

---

_This report is generated from normalized scanner findings and the security gate report. It does not replace manual security review._
