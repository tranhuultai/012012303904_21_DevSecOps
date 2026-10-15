#!/usr/bin/env python3
"""Normalize Semgrep, Gitleaks and Trivy JSON reports."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


SCHEMA_VERSION = "1.0"

SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
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

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# This file is expected at Code/DevSecOps/tools/test/normalize_findings.py.
PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = PROJECT_DIR / "schemas" / "finding.schema.json"


def load_json(path):
    """Load JSON and report missing or malformed files clearly."""
    if path is None:
        return None

    report_path = Path(path)
    if not report_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")

    try:
        with report_path.open("r", encoding="utf-8-sig") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {report_path}: "
            f"line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error


def require_object(data, source):
    """Ensure a report's root is a JSON object."""
    if not isinstance(data, dict):
        raise ValueError(f"{source} report must be a JSON object.")


def require_list(value, source):
    """Ensure a report section is a JSON array."""
    if not isinstance(value, list):
        raise ValueError(f"{source} must be a JSON array.")


def normalize_path(value):
    """Normalize paths to repository-relative POSIX paths."""
    if value is None or value == "":
        return None

    path = str(value).replace("\\", "/")

    while path.startswith("./"):
        path = path[2:]

    # Normalize an absolute checkout path when possible.
    marker = "/Code/DevSecOps/"
    if marker in path:
        path = "Code/DevSecOps/" + path.split(marker, 1)[1]

    return path


def normalize_severity(value, default="INFO"):
    """Map tool-specific severity labels to the schema's allowed values."""
    if value is None or value == "":
        return default

    severity = SEVERITY_MAP.get(str(value).strip().upper(), default)
    return severity if severity in VALID_SEVERITIES else default


def normalize_line(value):
    """Return a positive integer line number or None."""
    if isinstance(value, bool):
        return None

    if isinstance(value, int) and value >= 1:
        return value

    return None


def normalize_cve(value):
    """Return a normalized CVE identifier or None."""
    if not isinstance(value, str):
        return None

    value = value.strip()
    if CVE_PATTERN.fullmatch(value):
        return value.upper()

    return None


def normalize_references(references):
    """Keep unique HTTP(S) URLs only."""
    if not isinstance(references, list):
        return []

    safe_references = set()

    for reference in references:
        if not isinstance(reference, str):
            continue

        reference = reference.strip()
        try:
            parsed = urlparse(reference)
        except ValueError:
            continue

        if (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname
        ):
            safe_references.add(reference)

    return sorted(safe_references)


def make_fingerprint(tool, rule_id, file, line, cve, package=None):
    """Create a deterministic identifier without secret contents."""
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
    """Build one finding matching the normalized schema."""
    safe_rule_id = str(rule_id or "unknown").strip() or "unknown"
    safe_title = str(title or safe_rule_id).strip() or "Security finding"
    safe_message = str(message or "")

    file = normalize_path(file)
    line_start = normalize_line(line_start)
    line_end = normalize_line(line_end)
    cve = normalize_cve(cve)

    fingerprint = make_fingerprint(
        tool=tool,
        rule_id=safe_rule_id,
        file=file,
        line=line_start,
        cve=cve,
        package=package,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "finding_id": f"{tool}:{fingerprint[:16]}",
        "tool": tool,
        "rule_id": safe_rule_id,
        "category": category,
        "severity": normalize_severity(severity),
        "title": safe_title,
        "message": safe_message,
        "file": file,
        "line_start": line_start,
        "line_end": line_end,
        "cve": cve,
        "fingerprint": fingerprint,
        "status": "open",
        "references": normalize_references(references),
    }


def parse_semgrep(data):
    """Convert a Semgrep JSON report to normalized findings."""
    if data is None:
        return []

    require_object(data, "Semgrep")
    results = data.get("results", [])
    require_list(results, "Semgrep results")

    findings = []

    for index, item in enumerate(results):
        if not isinstance(item, dict):
            raise ValueError(
                f"Semgrep result at index {index} must be an object."
            )

        extra = item.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}

        metadata = extra.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        start = item.get("start") or {}
        end = item.get("end") or {}

        if not isinstance(start, dict):
            start = {}
        if not isinstance(end, dict):
            end = {}

        references = metadata.get("references", [])
        if isinstance(references, str):
            references = [references]

        severity = (
            extra.get("severity")
            or metadata.get("severity")
            or "INFO"
        )

        findings.append(
            make_finding(
                tool="semgrep",
                rule_id=item.get("check_id"),
                category="sast",
                severity=severity,
                title=item.get("check_id") or "Semgrep finding",
                message=extra.get("message"),
                file=item.get("path"),
                line_start=start.get("line"),
                line_end=end.get("line"),
                references=references,
            )
        )

    return findings


def parse_gitleaks(data):
    """Convert a Gitleaks JSON report without exposing secret values."""
    if data is None:
        return []

    if isinstance(data, dict):
        data = data.get("findings", [])

    require_list(data, "Gitleaks findings")

    findings = []

    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(
                f"Gitleaks finding at index {index} must be an object."
            )

        rule_id = item.get("RuleID") or item.get("Description")
        description = item.get("Description") or rule_id

        # Never copy Secret, Match, or other credential values.
        findings.append(
            make_finding(
                tool="gitleaks",
                rule_id=rule_id,
                category="secret",
                severity="HIGH",
                title=description or "Potential secret detected",
                message=(
                    "Potential secret detected. Secret values are omitted "
                    "from the normalized report."
                ),
                file=item.get("File"),
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                references=[],
            )
        )

    return findings


def parse_trivy(data):
    """Convert Trivy vulnerability results to normalized findings."""
    if data is None:
        return []

    require_object(data, "Trivy")
    results = data.get("Results", []) or []
    require_list(results, "Trivy Results")

    findings = []

    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(
                f"Trivy result at index {result_index} must be an object."
            )

        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities") or []
        require_list(
            vulnerabilities,
            f"Trivy vulnerabilities in result {result_index}",
        )

        for vuln_index, vuln in enumerate(vulnerabilities):
            if not isinstance(vuln, dict):
                raise ValueError(
                    "Trivy vulnerability at "
                    f"result {result_index}, index {vuln_index} "
                    "must be an object."
                )

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
                message_parts.append(str(vuln["Description"]))

            # Use a fresh list; do not mutate the source report.
            references = list(vuln.get("References") or [])
            primary_url = vuln.get("PrimaryURL")
            if primary_url:
                references.append(primary_url)

            findings.append(
                make_finding(
                    tool="trivy",
                    rule_id=vuln_id,
                    category="sca",
                    severity=vuln.get("Severity"),
                    title=(
                        vuln.get("Title")
                        or vuln_id
                        or "Dependency vulnerability"
                    ),
                    message="; ".join(message_parts),
                    file=target,
                    cve=vuln_id,
                    references=references,
                    package=package,
                )
            )

    return findings


def validate_findings(findings, schema_path):
    """Validate normalized findings against the JSON Schema."""
    if not schema_path.is_file():
        raise FileNotFoundError(f"Schema not found: {schema_path}")

    try:
        import jsonschema
    except ImportError as error:
        raise RuntimeError(
            "Schema validation requires jsonschema. Install it with: "
            "python -m pip install jsonschema"
        ) from error

    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        raise ValueError("Finding schema must be a JSON object.")

    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema, format_checker=jsonschema.FormatChecker())

    errors = []

    for index, finding in enumerate(findings):
        for error in validator.iter_errors(finding):
            location = ".".join(str(part) for part in error.absolute_path)
            location = location or "<root>"
            errors.append(
                f"Finding #{index} ({finding.get('finding_id', 'unknown')}), "
                f"{location}: {error.message}"
            )

    if errors:
        formatted = "\n".join(f"- {error}" for error in errors)
        raise ValueError(
            f"Schema validation failed with {len(errors)} error(s):\n"
            f"{formatted}"
        )


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
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA),
        help="Path to finding.schema.json",
    )
    parser.add_argument(
        "--skip-schema-validation",
        action="store_true",
        help="Skip schema validation (not recommended for CI)",
    )
    args = parser.parse_args()

    try:
        findings = []
        findings.extend(parse_semgrep(load_json(args.semgrep)))
        findings.extend(parse_gitleaks(load_json(args.gitleaks)))
        findings.extend(parse_trivy(load_json(args.trivy)))

        # Validate before writing so invalid results do not replace the
        # last known-good output file.
        if not args.skip_schema_validation:
            validate_findings(findings, Path(args.schema))

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(findings, file, indent=2, ensure_ascii=False)
            file.write("\n")

        print(f"Normalized {len(findings)} finding(s).")
        print(f"Output: {output_path}")

        counts = {}
        for finding in findings:
            key = finding["tool"]
            counts[key] = counts.get(key, 0) + 1

        for tool in ("semgrep", "gitleaks", "trivy"):
            print(f"  {tool}: {counts.get(tool, 0)}")

    except (
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        json.JSONDecodeError,
    ) as error:
        print(f"Normalization failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())