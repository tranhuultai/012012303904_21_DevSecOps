#!/usr/bin/env python3
"""Policy-driven security gate for normalized DevSecOps findings."""

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
DECISION_ORDER = {"PASS": 0, "WARN": 1, "BLOCK": 2}

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = PROJECT_DIR / "reports" / "normalized_findings.json"
DEFAULT_OUTPUT = PROJECT_DIR / "reports" / "security_gate.json"
DEFAULT_POLICY = PROJECT_DIR / "policy" / "g1" / "policy.json"
DEFAULT_EXCEPTIONS = PROJECT_DIR / "policy" / "exceptions.json"


class GateError(Exception):
    """Raised when input, policy, or exception configuration is invalid."""


def load_json(path):
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise GateError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(
            f"Invalid JSON in {path}, line {exc.lineno}: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise GateError(f"Cannot read {path}: {exc}") from exc


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise GateError("Policy root must be a JSON object.")

    required = {
        "policy_version",
        "profile",
        "blocking_severities",
        "warning_severities",
        "informational_severities",
        "fail_on_invalid_policy",
        "exception_policy",
    }
    missing = required - policy.keys()
    if missing:
        raise GateError(f"Policy missing fields: {', '.join(sorted(missing))}")

    if not isinstance(policy["policy_version"], str) or not policy["policy_version"]:
        raise GateError("policy_version must be a non-empty string.")

    if policy["profile"] not in ("g0", "g1", "g2"):
        raise GateError("profile must be g0, g1, or g2.")

    groups = {}
    for field in (
        "blocking_severities",
        "warning_severities",
        "informational_severities",
    ):
        values = policy[field]
        if not isinstance(values, list):
            raise GateError(f"{field} must be a JSON array.")
        if any(not isinstance(value, str) or value not in SEVERITIES
               for value in values):
            raise GateError(f"{field} contains an unknown severity.")
        if len(values) != len(set(values)):
            raise GateError(f"{field} contains duplicate severities.")
        groups[field] = set(values)

    names = list(groups)
    for i, first in enumerate(names):
        for second in names[i + 1:]:
            overlap = groups[first] & groups[second]
            if overlap:
                raise GateError(
                    "Severity cannot appear in multiple policy groups: "
                    + ", ".join(sorted(overlap))
                )

    if not isinstance(policy["fail_on_invalid_policy"], bool):
        raise GateError("fail_on_invalid_policy must be boolean.")

    exception_policy = policy["exception_policy"]
    if not isinstance(exception_policy, dict):
        raise GateError("exception_policy must be a JSON object.")

    for field in ("enabled", "require_reason", "require_expiry"):
        if not isinstance(exception_policy.get(field), bool):
            raise GateError(f"exception_policy.{field} must be boolean.")

    max_days = exception_policy.get("max_validity_days")
    if (
        isinstance(max_days, bool)
        or not isinstance(max_days, int)
        or max_days < 1
    ):
        raise GateError("max_validity_days must be a positive integer.")

    if exception_policy.get("expired_exception_action") != "block":
        raise GateError(
            "This implementation supports expired_exception_action='block' only."
        )

    return policy


def validate_findings(findings):
    if not isinstance(findings, list):
        raise GateError("Normalized findings must be a JSON array.")

    required = {"finding_id", "severity"}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise GateError(f"Finding at index {index} must be an object.")
        missing = required - finding.keys()
        if missing:
            raise GateError(
                f"Finding at index {index} missing fields: "
                + ", ".join(sorted(missing))
            )
        if not isinstance(finding["finding_id"], str) or not finding["finding_id"]:
            raise GateError(f"Finding at index {index} has invalid finding_id.")
        if finding["severity"] not in SEVERITIES:
            raise GateError(
                f"Finding {finding['finding_id']} has unknown severity: "
                f"{finding['severity']}"
            )

    return findings


def load_exceptions(path, exception_policy):
    if not exception_policy["enabled"]:
        return []

    if path is None:
        return []

    data = load_json(path)
    if not isinstance(data, list):
        raise GateError("Exceptions file must contain a JSON array.")

    today = date.today()
    max_days = exception_policy["max_validity_days"]
    validated = []
    seen_ids = set()

    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise GateError(f"Exception at index {index} must be an object.")

        finding_id = item.get("finding_id")
        reason = item.get("reason")
        expires_on = item.get("expires_on")

        if not isinstance(finding_id, str) or not finding_id.strip():
            raise GateError(f"Exception at index {index} has invalid finding_id.")
        if finding_id in seen_ids:
            raise GateError(f"Duplicate exception for finding_id: {finding_id}")
        seen_ids.add(finding_id)

        if exception_policy["require_reason"]:
            if not isinstance(reason, str) or not reason.strip():
                raise GateError(
                    f"Exception {finding_id} requires a non-empty reason."
                )

        if exception_policy["require_expiry"] and not expires_on:
            raise GateError(
                f"Exception {finding_id} requires expires_on (YYYY-MM-DD)."
            )

        try:
            expiry = date.fromisoformat(expires_on)
        except (TypeError, ValueError) as exc:
            raise GateError(
                f"Exception {finding_id} has invalid expires_on; use YYYY-MM-DD."
            ) from exc

        if expiry < today:
            item = dict(item)
            item["_exception_status"] = "expired"
        else:
            if (expiry - today).days > max_days:
                raise GateError(
                    f"Exception {finding_id} exceeds max_validity_days "
                    f"({max_days})."
                )
            item = dict(item)
            item["_exception_status"] = "valid"

        validated.append(item)

    return validated


def evaluate_gate(findings, policy, exceptions):
    blocking = set(policy["blocking_severities"])
    warnings = set(policy["warning_severities"])
    informational = set(policy["informational_severities"])
    exception_policy = policy["exception_policy"]

    exception_map = {item["finding_id"]: item for item in exceptions}
    seen_findings = {item["finding_id"] for item in findings}

    unknown_exceptions = sorted(set(exception_map) - seen_findings)
    blockers = []
    warning_items = []
    informational_items = []
    excepted_items = []
    expired_exceptions = []
    evaluated = []

    for finding in findings:
        item = dict(finding)
        finding_id = finding["finding_id"]
        severity = finding["severity"]
        exception = exception_map.get(finding_id)

        if exception and exception["_exception_status"] == "expired":
            expired_exceptions.append({
                "finding_id": finding_id,
                "reason": exception.get("reason", ""),
                "expires_on": exception.get("expires_on"),
            })
            item["gate_status"] = "BLOCK"
            item["gate_reason"] = "Exception expired"
            blockers.append(item)

        elif exception and exception["_exception_status"] == "valid":
            item["gate_status"] = "EXCEPTED"
            item["gate_reason"] = "Valid time-limited exception"
            item["exception_reason"] = exception.get("reason", "")
            item["exception_expires_on"] = exception.get("expires_on")
            excepted_items.append(item)

        elif severity in blocking:
            item["gate_status"] = "BLOCK"
            item["gate_reason"] = "Severity is blocking under policy"
            blockers.append(item)

        elif severity in warnings:
            item["gate_status"] = "WARN"
            item["gate_reason"] = "Severity is warning under policy"
            warning_items.append(item)

        elif severity in informational:
            item["gate_status"] = "INFO"
            item["gate_reason"] = "Informational finding"
            informational_items.append(item)

        else:
            # Fail closed: an unclassified severity must never pass silently.
            raise GateError(
                f"Finding {finding_id} severity {severity} is not classified "
                "by the selected policy."
            )

        evaluated.append(item)

    if blockers:
        decision = "BLOCK"
    elif warning_items or expired_exceptions:
        decision = "WARN"
    else:
        decision = "PASS"

    # Expired exceptions are already blockers when the policy action is "block".
    if expired_exceptions:
        decision = "BLOCK"

    return {
        "gate_version": "1.0",
        "generated_on": date.today().isoformat(),
        "policy": {
            "profile": policy["profile"],
            "policy_version": policy["policy_version"],
        },
        "decision": decision,
        "passed": decision != "BLOCK",
        "summary": {
            "total_findings": len(findings),
            "blockers": len(blockers),
            "warnings": len(warning_items),
            "informational": len(informational_items),
            "excepted": len(excepted_items),
            "expired_exceptions": len(expired_exceptions),
        },
        "blocking_severities": policy["blocking_severities"],
        "warning_severities": policy["warning_severities"],
        "informational_severities": policy["informational_severities"],
        "blockers": blockers,
        "warnings": warning_items,
        "informational_findings": informational_items,
        "excepted_findings": excepted_items,
        "expired_exceptions": expired_exceptions,
        "unused_exceptions": unknown_exceptions,
        "findings": evaluated,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate normalized security findings using a JSON policy."
    )
    parser.add_argument("--input", default=str(DEFAULT_INPUT),
                        help="Path to normalized findings JSON.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="Path for the security gate JSON report.")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY),
                        help="Path to policy JSON (default: G1).")
    parser.add_argument("--exceptions", default=None,
                        help="Optional JSON array of time-limited exceptions.")
    args = parser.parse_args()

    try:
        policy = validate_policy(load_json(Path(args.policy)))
        findings = validate_findings(load_json(Path(args.input)))

        exception_path = Path(args.exceptions) if args.exceptions else None
        exceptions = load_exceptions(exception_path, policy["exception_policy"])
        result = evaluate_gate(findings, policy, exceptions)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        print("=" * 60)
        print("DEVSECOPS SECURITY GATE")
        print("=" * 60)
        print(f"Policy: {result['policy']['profile']} "
              f"(version {result['policy']['policy_version']})")
        print(f"Input: {Path(args.input).resolve()}")
        print(f"Total findings: {result['summary']['total_findings']}")
        print("Blocking severities: "
              + (", ".join(result["blocking_severities"]) or "None"))
        print("Warning severities: "
              + (", ".join(result["warning_severities"]) or "None"))
        print(f"Blockers: {result['summary']['blockers']}")
        print(f"Warnings: {result['summary']['warnings']}")
        print(f"Excepted: {result['summary']['excepted']}")
        print(f"Expired exceptions: {result['summary']['expired_exceptions']}")
        print(f"Report: {output_path.resolve()}")
        print(f"RESULT: {result['decision']}")

        for item in result["findings"]:
            severity = item["severity"]
            status = item["gate_status"]
            title = item.get("title") or item.get("rule_id") or item["finding_id"]
            file_path = item.get("file") or item.get("path") or "unknown"
            line = item.get("line_start") or item.get("line") or "?"
            print(f"[{status}] [{severity}] {item['finding_id']}: "
                  f"{title} ({file_path}:{line})")

        if result["unused_exceptions"]:
            print("WARNING: unused exceptions: "
                  + ", ".join(result["unused_exceptions"]))

        return 1 if result["decision"] == "BLOCK" else 0

    except (GateError, OSError, TypeError, ValueError) as exc:
        print(f"Security gate execution error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())