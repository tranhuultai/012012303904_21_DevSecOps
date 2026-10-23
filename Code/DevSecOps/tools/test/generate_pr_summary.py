#!/usr/bin/env python3
"""Generate a Markdown Pull Request summary from normalized findings and gate results."""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
TOOLS = ["semgrep", "gitleaks", "trivy"]
VALID_DECISIONS = {"PASS", "WARN", "BLOCK"}

PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_FINDINGS = PROJECT_DIR / "reports" / "normalized_findings.json"
DEFAULT_GATE = PROJECT_DIR / "reports" / "security_gate.json"
DEFAULT_OUTPUT = PROJECT_DIR / "reports" / "pr_summary.md"


def load_json(path):
    """Load a JSON file and report malformed input clearly."""
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
    """Validate the minimum fields required for the summary."""
    if not isinstance(data, list):
        raise ValueError("Normalized findings must be a JSON array.")

    required = {"finding_id", "tool", "severity", "title", "status"}

    for index, finding in enumerate(data):
        if not isinstance(finding, dict):
            raise ValueError(f"Finding #{index} must be a JSON object.")

        missing = required - finding.keys()
        if missing:
            raise ValueError(
                f"Finding #{index} is missing fields: "
                + ", ".join(sorted(missing))
            )

        if finding["severity"] not in SEVERITIES:
            raise ValueError(
                f"Invalid severity in finding #{index}: "
                f"{finding['severity']!r}"
            )

        if not isinstance(finding["finding_id"], str):
            raise ValueError(f"Finding #{index} has an invalid finding_id.")

    return data


def markdown_escape(value):
    """Escape common Markdown table characters."""
    text = str(value if value is not None else "—")
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("`", "\\`")
    )


def format_location(finding):
    """Format a finding's file and optional line number."""
    file_path = finding.get("file") or "Unknown location"
    line = finding.get("line_start")

    if line is not None:
        return f"{file_path}:{line}"

    return str(file_path)


def summarize_counts(findings):
    """Count findings by severity and scanner."""
    by_severity = Counter(
        finding["severity"] for finding in findings
    )
    by_tool = Counter(
        finding.get("tool", "unknown") for finding in findings
    )

    return by_severity, by_tool


def get_gate_decision(gate_report):
    """Read and validate the gate decision."""
    if gate_report is None:
        return "UNKNOWN"

    decision = str(gate_report.get("decision", "")).upper()

    if decision not in VALID_DECISIONS:
        raise ValueError(
            "Gate report must contain decision PASS, WARN, or BLOCK."
        )

    return decision


def get_gate_items(gate_report, findings, key, decision):
    """Get findings listed in a gate report, with a safe fallback."""
    if gate_report is not None:
        items = gate_report.get(key, [])
        if not isinstance(items, list):
            raise ValueError(f"Gate report field {key!r} must be an array.")
        return items

    # Fallback when no gate report was supplied.
    return [
        finding
        for finding in findings
        if finding.get("severity") in decision
    ]


def render_finding_table(findings, empty_message):
    """Render findings as a Markdown table."""
    if not findings:
        return empty_message

    lines = [
        "| Severity | Tool | Finding | Location | ID |",
        "|---|---|---|---|---|",
    ]

    for finding in findings:
        severity = markdown_escape(finding.get("severity"))
        tool = markdown_escape(finding.get("tool"))
        title = markdown_escape(finding.get("title"))
        location = markdown_escape(format_location(finding))
        finding_id = markdown_escape(finding.get("finding_id"))

        lines.append(
            f"| {severity} | {tool} | {title} | "
            f"`{location}` | `{finding_id}` |"
        )

    return "\n".join(lines)


def build_summary(findings, gate_report, title="DevSecOps Security Summary"):
    """Build the complete Markdown report."""
    decision = get_gate_decision(gate_report)
    by_severity, by_tool = summarize_counts(findings)

    gate_summary = {}
    if gate_report is not None:
        gate_summary = gate_report.get("summary", {})
        if not isinstance(gate_summary, dict):
            raise ValueError("Gate report summary must be a JSON object.")

    blockers = (
        gate_report.get("blockers", [])
        if gate_report is not None
        else []
    )
    warnings = (
        gate_report.get("warnings", [])
        if gate_report is not None
        else []
    )

    if not isinstance(blockers, list) or not isinstance(warnings, list):
        raise ValueError("Gate blockers and warnings must be JSON arrays.")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# {title}",
        "",
        f"> Generated automatically on {generated_at}.",
        "",
        "## Gate result",
        "",
        f"**Decision: {decision}**",
        "",
    ]

    if decision == "BLOCK":
        lines.append(
            "The security gate found blocking issues. "
            "Review and remediate them before merging or deploying."
        )
    elif decision == "WARN":
        lines.append(
            "Warnings were detected. The current policy allows the pipeline "
            "to continue, but the findings should be reviewed."
        )
    elif decision == "PASS":
        lines.append(
            "No findings violated the configured blocking policy."
        )
    else:
        lines.append(
            "No valid gate report was supplied. The gate decision is unknown."
        )

    lines.extend([
        "",
        "## Overview",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Total findings | {len(findings)} |",
        f"| Blockers | {gate_summary.get('blockers', len(blockers))} |",
        f"| Warnings | {gate_summary.get('warnings', len(warnings))} |",
        f"| Active exceptions used | "
        f"{gate_summary.get('active_exceptions_used', 0)} |",
        f"| Expired exceptions | "
        f"{gate_summary.get('expired_exceptions', 0)} |",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ])

    for severity in SEVERITIES:
        lines.append(f"| {severity} | {by_severity.get(severity, 0)} |")

    lines.extend([
        "",
        "## Findings by tool",
        "",
        "| Tool | Count |",
        "|---|---:|",
    ])

    for tool in TOOLS:
        lines.append(f"| {tool} | {by_tool.get(tool, 0)} |")

    other_tools = sorted(set(by_tool) - set(TOOLS))
    for tool in other_tools:
        lines.append(f"| {markdown_escape(tool)} | {by_tool[tool]} |")

    lines.extend([
        "",
        "## Blocking findings",
        "",
        render_finding_table(
            blockers,
            "No blocking findings reported by the security gate.",
        ),
        "",
        "## Warning findings",
        "",
        render_finding_table(
            warnings,
            "No warning findings reported by the security gate.",
        ),
        "",
    ])

    if gate_report is not None:
        expired = gate_report.get("expired_exceptions", [])
        unused = gate_report.get("unused_exceptions", [])

        lines.extend([
            "## Exception review",
            "",
            f"- Expired exceptions: **{len(expired)}**",
            f"- Unused exceptions: **{len(unused)}**",
            "",
        ])

        if expired:
            lines.extend([
                "### Expired exceptions",
                "",
                "| Finding ID | Expiry date |",
                "|---|---|",
            ])
            for item in expired:
                if isinstance(item, dict):
                    lines.append(
                        f"| `{markdown_escape(item.get('finding_id'))}` "
                        f"| {markdown_escape(item.get('expires_on'))} |"
                    )
            lines.append("")

        if unused:
            lines.extend([
                "### Unused exceptions",
                "",
            ])
            for finding_id in unused:
                lines.append(f"- `{markdown_escape(finding_id)}`")
            lines.append("")

    lines.extend([
        "---",
        "",
        "_This report is generated from normalized scanner findings and "
        "the security gate report. It does not replace manual security review._",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Markdown PR summary from security reports."
    )
    parser.add_argument(
        "--findings",
        default=str(DEFAULT_FINDINGS),
        help="Path to normalized_findings.json",
    )
    parser.add_argument(
        "--gate",
        default=str(DEFAULT_GATE),
        help="Path to security_gate.json",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to the Markdown output file",
    )
    parser.add_argument(
        "--title",
        default="DevSecOps Security Summary",
        help="Title of the Markdown report",
    )
    parser.add_argument(
        "--allow-missing-gate",
        action="store_true",
        help="Generate a summary even if the gate report is missing",
    )
    args = parser.parse_args()

    try:
        findings = validate_findings(load_json(args.findings))

        gate_path = Path(args.gate)
        if gate_path.is_file():
            gate_report = load_json(gate_path)
            if not isinstance(gate_report, dict):
                raise ValueError("Gate report must be a JSON object.")
        elif args.allow_missing_gate:
            gate_report = None
        else:
            raise FileNotFoundError(
                f"Gate report not found: {gate_path}. "
                "Run security_gate.py first or use --allow-missing-gate."
            )

        markdown = build_summary(findings, gate_report, args.title)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")

        print(f"PR summary generated: {output_path}")
        print(f"Findings: {len(findings)}")
        print(
            "Gate decision: "
            + (
                get_gate_decision(gate_report)
                if gate_report is not None
                else "UNKNOWN"
            )
        )

        return 0

    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"PR summary generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())