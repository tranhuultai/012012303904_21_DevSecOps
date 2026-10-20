# DevSecOps Security Summary

> Generated automatically on 2026-10-20 03:49 UTC.

## Gate result

**Decision: BLOCK**

The security gate found blocking issues. Review and remediate them before merging or deploying.

## Overview

| Metric | Count |
|---|---:|
| Total findings | 3 |
| Blockers | 3 |
| Warnings | 0 |
| Active exceptions used | 0 |
| Expired exceptions | 1 |

## Findings by severity

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 3 |
| LOW | 0 |
| INFO | 0 |

## Findings by tool

| Tool | Count |
|---|---:|
| semgrep | 2 |
| gitleaks | 0 |
| trivy | 1 |

## Blocking findings

| Severity | Tool | Finding | Location | ID |
|---|---|---|---|---|
| MEDIUM | semgrep | terraform.aws.security.aws-db-instance-no-logging.aws-db-instance-no-logging | `Code/DevSecOps/infra/rds.tf:30` | `semgrep:a7eb3c3198ebce01` |
| MEDIUM | semgrep | python.lang.security.audit.eval-detected.eval-detected | `Code/DevSecOps/src/app/vulnerable_examples.py:47` | `semgrep:3e9ab840300ae18a` |
| MEDIUM | trivy | pytest: pytest: Denial of Service or Privilege Escalation via insecure temporary directory handling | `src/requirements.txt` | `trivy:d3c1749797a2c9f2` |

## Warning findings

No warning findings reported by the security gate.

## Exception review

- Expired exceptions: **1**
- Unused exceptions: **0**

### Expired exceptions

| Finding ID | Expiry date |
|---|---|
| `trivy:d3c1749797a2c9f2` | 2026-10-19 |

---

_This report is generated from normalized scanner findings and the security gate report. It does not replace manual security review._
