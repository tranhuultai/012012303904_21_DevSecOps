#!/usr/bin/env python3
"""Evaluate normalized DevSecOps findings against a configurable policy."""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_STATUSES = {"open", "fixed", "accepted", "false_positive"}

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = PROJECT_DIR / "reports" / "normalized_findings.json"
DEFAULT_OUTPUT = PROJECT_DIR / "reports" / "security_gate.json"


def load_json(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        with path.open("r", encoding="utf-8-sig") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {path}, line {error.lineno}: {error.msg}"
        ) from error


def validate_findings(data):
    if not isinstance(data, list):
        raise ValueError("Normalized findings must be a JSON array.")

    required = {
        "finding_id", "tool", "severity", "title", "status", "fingerprint"
    }

    for index, finding in enumerate(data):
        if not isinstance(finding, dict):
            raise ValueError(f"Finding #{index} must be an object.")

        missing = required - finding.keys()
        if missing:
            raise ValueError(
                f"Finding #{index} is missing: {', '.join(sorted(missing))}"
            )

        if finding["severity"] not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity for {finding['finding_id']}: "
                f"{finding['severity']!r}"
            )

        if finding["status"] not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status for {finding['finding_id']}: "
                f"{finding['status']!r}"
            )

        for field in ("finding_id", "tool", "title", "fingerprint"):
            if not isinstance(finding[field], str) or not finding[field].strip():
                raise ValueError(
                    f"Finding #{index} has an invalid {field}."
                )

    return data


def load_exceptions(path, today):
    if not path:
        return {}, []

    data = load_json(path)
    if not isinstance(data, list):
        raise ValueError("Exceptions file must contain a JSON array.")

    active = {}
    expired = {}
    seen = set()

    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Exception #{index} must be an object.")

        finding_id = item.get("finding_id")
        reason = item.get("reason")
        expires_on = item.get("expires_on")

        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError(f"Exception #{index} requires finding_id.")
        if finding_id in seen:
            raise ValueError(f"Duplicate exception: {finding_id}")
        seen.add(finding_id)

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"Exception for {finding_id} requires reason.")
        if not isinstance(expires_on, str):
            raise ValueError(f"Exception for {finding_id} requires expires_on.")

        try:
            expiry = date.fromisoformat(expires_on)
        except ValueError as error:
            raise ValueError(
                f"Invalid expires_on for {finding_id}: {expires_on!r}"
            ) from error

        if expiry.isoformat() != expires_on:
            raise ValueError(
                f"Use YYYY-MM-DD for exception {finding_id}."
            )

        entry = {
            "finding_id": finding_id,
            "reason": reason.strip(),
            "expires_on": expires_on,
        }

        if expiry >= today:
            active[finding_id] = entry
        else:
            expired[finding_id] = entry

    return active, list(expired.values())


def evaluate(findings, block_levels, warn_levels, active_exceptions,
             expired_exceptions, today):
    blockers = []
    warnings = []
    evaluated = []
    used_exceptions = set()
    by_severity = {severity: 0 for severity in
                   ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    by_tool = {}

    expired_by_id = {
        item["finding_id"]: item for item in expired_exceptions
    }

    for finding in findings:
        finding_id = finding["finding_id"]
        severity = finding["severity"]
        status = finding["status"]

        by_severity[severity] += 1
        by_tool[finding["tool"]] = by_tool.get(finding["tool"], 0) + 1

        item = {
            "finding_id": finding_id,
            "tool": finding["tool"],
            "severity": severity,
            "title": finding["title"],
            "status": status,
            "decision": "pass",
            "reason": "No blocking policy matched.",
        }

        if status in {"fixed", "accepted", "false_positive"}:
            item["reason"] = f"Finding status is {status}."
            evaluated.append(item)
            continue

        exception = active_exceptions.get(finding_id)
        if exception:
            used_exceptions.add(finding_id)
            item["decision"] = "exception"
            item["reason"] = exception["reason"]
            item["exception_expires_on"] = exception["expires_on"]
            evaluated.append(item)
            continue

        if finding_id in expired_by_id:
            item["reason"] = (
                "Exception expired on "
                + expired_by_id[finding_id]["expires_on"]
            )
            item["exception_expired"] = True

        if severity in block_levels:
            item["decision"] = "block"
            blockers.append(item.copy())
        elif severity in warn_levels:
            item["decision"] = "warn"
            warnings.append(item.copy())

        evaluated.append(item)

    decision = "BLOCK" if blockers else ("WARN" if warnings else "PASS")

    return {
        "gate_version": "1.0",
        "evaluated_on": today.isoformat(),
        "decision": decision,
        "passed": not blockers,
        "policy": {
            "block_severities": sorted(block_levels),
            "warn_severities": sorted(warn_levels),
        },
        "summary": {
            "total_findings": len(findings),
            "blockers": len(blockers),
            "warnings": len(warnings),
            "active_exceptions_used": len(used_exceptions),
            "expired_exceptions": len(expired_exceptions),
            "by_severity": by_severity,
            "by_tool": dict(sorted(by_tool.items())),
        },
        "blockers": blockers,
        "warnings": warnings,
        "expired_exceptions": expired_exceptions,
        "unused_exceptions": sorted(
            set(active_exceptions) - used_exceptions
        ),
        "findings": evaluated,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate normalized security findings."
    )
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument(
        "--block", nargs="+", default=["CRITICAL", "HIGH"],
        help="Severities that block the pipeline."
    )
    parser.add_argument(
        "--warn", nargs="*", default=["MEDIUM"],
        help="Severities that produce warnings."
    )
    parser.add_argument(
        "--exceptions",
        help="Optional JSON file containing time-limited exceptions."
    )
    args = parser.parse_args()

    try:
        today = date.today()
        findings = validate_findings(load_json(args.input))

        block_levels = {item.upper() for item in args.block}
        warn_levels = {item.upper() for item in args.warn}

        invalid = (block_levels | warn_levels) - VALID_SEVERITIES
        if invalid:
            raise ValueError(
                f"Unknown severity: {', '.join(sorted(invalid))}"
            )

        overlap = block_levels & warn_levels
        if overlap:
            raise ValueError(
                "A severity cannot be both blocking and warning: "
                + ", ".join(sorted(overlap))
            )

        active, expired = load_exceptions(args.exceptions, today)
        report = evaluate(
            findings, block_levels, warn_levels, active, expired, today
        )

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
            file.write("\n")

        summary = report["summary"]
        print("=" * 60)
        print("DEVSECOPS SECURITY GATE")
        print("=" * 60)
        print(f"Input: {args.input}")
        print(f"Total findings: {summary['total_findings']}")
        print(f"Blocking severities: {', '.join(sorted(block_levels))}")
        print(f"Warning severities: {', '.join(sorted(warn_levels))}")
        print(f"Blockers: {summary['blockers']}")
        print(f"Warnings: {summary['warnings']}")
        print(f"Report: {output}")
        print(f"RESULT: {report['decision']}")

        for item in report["blockers"]:
            print(
                f"[BLOCK] [{item['severity']}] "
                f"{item['finding_id']}: {item['title']}"
            )
        for item in report["warnings"]:
            print(
                f"[WARN] [{item['severity']}] "
                f"{item['finding_id']}: {item['title']}"
            )

        # 0 = PASS/WARN, 1 = BLOCK, 2 = execution/configuration error.
        return 1 if report["blockers"] else 0

    except (OSError, ValueError, TypeError) as error:
        print(f"Security gate execution error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())