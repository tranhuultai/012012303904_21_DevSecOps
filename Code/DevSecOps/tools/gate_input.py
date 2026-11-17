import argparse
import json
import sys
from pathlib import Path

import jsonschema
import yaml


# Gộp findings đã chuẩn hóa, ngoại lệ và ngữ cảnh thành gate_input.json cho Conftest.
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--findings", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", required=True)
    p.add_argument("--policy", required=True, choices=["g0", "g1", "g2"])
    p.add_argument("--out", required=True)
    p.add_argument(
        "--exceptions-schema",
        default=str(Path(__file__).resolve().parents[1] / "schemas" / "exception.schema.json"),
    )
    a = p.parse_args()

    with open(a.findings, encoding="utf-8") as fh:
        findings = json.load(fh)
    # Fail-closed: object thiếu khóa "findings" là đầu vào hỏng, không được coi là quét sạch.
    if isinstance(findings, dict):
        if "findings" not in findings:
            raise SystemExit(f"findings không hợp lệ: object thiếu khóa 'findings' ({a.findings})")
        findings = findings["findings"]
    if not isinstance(findings, list):
        raise SystemExit(f"findings không hợp lệ: cần mảng ({a.findings})")

    with open(a.exceptions, encoding="utf-8") as fh:
        exceptions = yaml.safe_load(fh) or []

    with open(a.exceptions_schema, encoding="utf-8") as fh:
        exception_schema = json.load(fh)
    jsonschema.validate(exceptions, exception_schema)

    gate_input = {
        "findings": findings,
        "exceptions": exceptions,
        "context": {"today": a.today, "policy": a.policy},
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(gate_input, fh, ensure_ascii=False, indent=2)
    print(f"gate_input: {len(findings)} findings, {len(exceptions)} exceptions -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
