#!/usr/bin/env python3
"""Chuyển kết quả `conftest test --output json` thành báo cáo gate dạng JSON
mà tools/test/generate_pr_summary.py hiểu được (decision/blockers/warnings).

Lý do: pipeline chạy gate bằng Conftest/Rego (policy as code), còn bộ tóm tắt
PR được viết quanh định dạng security_gate.json của script Python. Cầu nối
này giữ một nguồn sự thật duy nhất cho quyết định gate: chính sách Rego.

Quy tắc ánh xạ:
    - Có bất kỳ `deny`  nào  => decision BLOCK, mục deny vào "blockers".
    - Không deny, có `warn`  => decision WARN, mục warn vào "warnings".
    - Không deny, không warn => decision PASS.
    - Conftest báo failed nhưng không parse được mục nào => BLOCK (fail-closed).

Dùng:
    python tools/conftest_gate_report.py \
        --conftest gate-result.json \
        --findings reports/enriched_findings.json \
        --policy g2 \
        --out gate_report.json
"""

import argparse
import json
import sys
from pathlib import Path


def load_json(path):
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def collect_results(conftest_data):
    """Trả về danh sách dict {type: deny|warn|..., msg, ...} từ output Conftest."""
    if isinstance(conftest_data, dict):
        raw = conftest_data.get("results", [])
    else:
        raw = conftest_data
    if not isinstance(raw, list):
        raise ValueError("Conftest JSON must contain a 'results' array.")
    return raw


RESULT_KEY_BY_QUERY = {"deny": "failures", "warn": "warnings"}


def extract_items(results, query):
    """Lấy thông điệp của một query từ output Conftest.

    Mỗi phần tử results của Conftest có dạng:
        {"filename": ..., "success": bool, "failures": [...], "warnings": [...]}
    Chỉ các mục trong failures/warnings mới là phát hiện; result sạch
    (mảng rỗng) không sinh mục nào.
    """
    key = RESULT_KEY_BY_QUERY.get(query, "failures")
    items = []
    for result in results:
        if not isinstance(result, dict):
            continue
        entries = result.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            msg = entry.get("msg") if isinstance(entry, dict) else str(entry)
            items.append(
                {
                    "finding_id": f"{query}:{len(items)}",
                    "rule_id": query,
                    "severity": "CRITICAL" if query == "deny" else "MEDIUM",
                    "title": str(msg or query),
                    "message": str(msg or ""),
                    "file": result.get("filename"),
                    "status": "open",
                }
            )
    return items


def build_report(results, findings, policy):
    deny_items = extract_items(results, "deny")
    warn_items = extract_items(results, "warn")

    # Fail-closed: trường failures tồn tại nhưng không phải danh sách (định dạng
    # đổi) => không đọc được mục nào; coi như chặn để không bỏ lọt.
    unparsed = [
        r for r in results
        if isinstance(r, dict)
        and "failures" in r
        and not isinstance(r.get("failures"), list)
        and r.get("failures")
    ]
    if not deny_items and not warn_items and unparsed:
        deny_items = [
            {
                "finding_id": "deny:unparsed",
                "rule_id": "fail-closed",
                "severity": "CRITICAL",
                "title": "Conftest reported failures that could not be parsed",
                "message": "Fail-closed: unparsed Conftest failures are treated as blockers.",
                "file": None,
                "status": "open",
            }
        ]

    if deny_items:
        decision = "BLOCK"
    elif warn_items:
        decision = "WARN"
    else:
        decision = "PASS"

    return {
        "gate_version": "1.0",
        "engine": "conftest-rego",
        "policy_profile": policy,
        "decision": decision,
        "passed": decision != "BLOCK",
        "summary": {
            "total_findings": len(findings) if isinstance(findings, list) else 0,
            "blockers": len(deny_items),
            "warnings": len(warn_items),
            "informational": 0,
            "excepted": 0,
            "expired_exceptions": 0,
        },
        "blockers": deny_items,
        "warnings": warn_items,
        "informational_findings": [],
        "excepted_findings": [],
        "expired_exceptions": [],
        "unused_exceptions": [],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Convert Conftest JSON output to gate report for PR summary."
    )
    parser.add_argument("--conftest", required=True)
    parser.add_argument("--findings", required=False, default=None)
    parser.add_argument("--policy", required=True, choices=["g0", "g1", "g2"])
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        results = collect_results(load_json(Path(args.conftest)))
        findings = []
        if args.findings:
            data = load_json(Path(args.findings))
            findings = data.get("findings", []) if isinstance(data, dict) else data

        report = build_report(results, findings, args.policy)

        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

        print(f"gate report: decision={report['decision']} -> {out_path}")
        print(
            f"  blockers={report['summary']['blockers']} "
            f"warnings={report['summary']['warnings']}"
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"conftest_gate_report failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
