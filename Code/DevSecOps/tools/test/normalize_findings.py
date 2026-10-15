#!/usr/bin/env python3
"""Normalize Semgrep, Gitleaks and Trivy JSON reports."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "ERROR": "HIGH",
    "MEDIUM": "MEDIUM",
    "WARNING": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "UNKNOWN": "INFO",
}

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def load_json(path):
    """Load a JSON report and fail clearly if it is invalid."""
    if path is None:
        return None

    report_path = Path(path)
    if not report_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")

    with report_path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def normalize_path(value):
    """Normalize paths to repository-relative POSIX paths."""
    if not value:
        return None

    path = str(value).replace("\\", "/")

    while path.startswith("./"):
        path = path[2:]

    # Remove an absolute checkout prefix if one is present.
    marker = "/Code/DevSecOps/"
    if marker in path:
        path = path.split(marker, 1)[1]
        path = "Code/DevSecOps/" + path
    elif path.startswith("Code/DevSecOps/"):
        pass

    return path


def normalize_severity(value, default="INFO"):
    if not value:
        return default

    return SEVERITY_MAP.get(str(value).upper(), default)


def normalize_cve(value):
    if value and CVE_PATTERN.fullmatch(str(value)):
        return str(value).upper()
    return None


def make_fingerprint(tool, rule_id, file, line, cve, package=None):
    """Create a stable identifier without including secret values."""
    parts = [
        tool,
        rule_id or "",
        file or "",
        str(line or ""),
        cve or "",
        package or "",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def make_finding(
    *,
    tool,
    rule_id,
    category,
    severity,
    title,
    message,
    file=None,
    line_start=None,
    line_end=None,
    cve=None,
    references=None,
    package=None,
):
    file = normalize_path(file)
    fingerprint = make_fingerprint(
        tool, rule_id, file, line_start, cve, package
    )

    safe_references = []
    for reference in references or []:
        if not isinstance(reference, str):
            continue
        parsed = urlparse(reference)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            safe_references.append(reference)

    safe_references = sorted(set(safe_references))

    return {
        "schema_version": "1.0",
        "finding_id": f"{tool}:{fingerprint[:16]}",
        "tool": tool,
        "rule_id": str(rule_id or "unknown"),
        "category": category,
        "severity": normalize_severity(severity),
        "title": str(title or rule_id or "Security finding"),
        "message": str(message or ""),
        "file": file,
        "line_start": line_start,
        "line_end": line_end,
        "cve": normalize_cve(cve),
        "fingerprint": fingerprint,
        "status": "open",
        "references": safe_references,
    }


def parse_semgrep(data):
    findings = []

    if data is None:
        return findings

    for item in data.get("results", []):
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}

        finding = make_finding(
            tool="semgrep",
            rule_id=item.get("check_id"),
            category="sast",
            severity=extra.get("severity"),
            title=item.get("check_id"),
            message=extra.get("message"),
            file=item.get("path"),
            line_start=start.get("line"),
            line_end=end.get("line"),
            references=extra.get("metadata", {}).get("references", []),
        )
        findings.append(finding)

    return findings


def parse_gitleaks(data):
    findings = []

    if data is None:
        return findings

    # Gitleaks reports are commonly JSON arrays.
    # Support an object wrapper as well for easier future integration.
    if isinstance(data, dict):
        data = data.get("findings", [])

    for item in data or []:
        rule_id = item.get("RuleID") or item.get("Description")
        file_path = item.get("File")

        # Do not copy Secret, Match or other credential values
        # into the normalized output.
        findings.append(
            make_finding(
                tool="gitleaks",
                rule_id=rule_id,
                category="secret",
                severity="HIGH",
                title=item.get("Description") or rule_id or "Secret detected",
                message="Potential secret detected. See the source report "
                        "for location details; secret values are omitted.",
                file=file_path,
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                references=[],
            )
        )

    return findings


def parse_trivy(data):
    findings = []

    if data is None:
        return findings

    for result in data.get("Results", []) or []:
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities") or []

        for vuln in vulnerabilities:
            vuln_id = vuln.get("VulnerabilityID")
            package = vuln.get("PkgName")
            installed = vuln.get("InstalledVersion")
            fixed = vuln.get("FixedVersion")

            message_parts = []
            if package:
                message_parts.append(f"Package: {package}")
            if installed:
                message_parts.append(f"Installed version: {installed}")
            if fixed:
                message_parts.append(f"Fixed version: {fixed}")
            if vuln.get("Description"):
                message_parts.append(vuln["Description"])

            references = vuln.get("References") or []
            if vuln.get("PrimaryURL"):
                references.append(vuln["PrimaryURL"])

            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=vuln_id,
                    category="sca",
                    severity=vuln.get("Severity"),
                    title=vuln.get("Title") or vuln_id or "Dependency vulnerability",
                    message="; ".join(message_parts),
                    file=target,
                    line_start=None,
                    line_end=None,
                    cve=vuln_id,
                    references=references,
                    package=package,
                )
            )

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Normalize Semgrep, Gitleaks and Trivy JSON reports."
    )
    parser.add_argument("--semgrep", help="Path to Semgrep JSON report")
    parser.add_argument("--gitleaks", help="Path to Gitleaks JSON report")
    parser.add_argument("--trivy", help="Path to Trivy JSON report")
    parser.add_argument(
        "--output",
        default="reports/normalized_findings.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    try:
        findings = []
        findings.extend(parse_semgrep(load_json(args.semgrep)))
        findings.extend(parse_gitleaks(load_json(args.gitleaks)))
        findings.extend(parse_trivy(load_json(args.trivy)))

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(findings, file, indent=2, ensure_ascii=False)
            file.write("\n")

        print(f"Normalized {len(findings)} finding(s).")
        print(f"Output: {output_path}")

    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"Normalization failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())