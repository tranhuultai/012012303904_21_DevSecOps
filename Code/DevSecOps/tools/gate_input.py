import argparse
import json
import sys

import yaml


# Gộp findings đã chuẩn hóa, ngoại lệ và ngữ cảnh thành gate_input.json cho Conftest.
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--findings", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", required=True)
    p.add_argument("--policy", required=True, choices=["g0", "g1", "g2"])
    p.add_argument("--out", required=True)
    a = p.parse_args()

    with open(a.findings, encoding="utf-8") as fh:
        findings = json.load(fh)
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    with open(a.exceptions, encoding="utf-8") as fh:
        exceptions = yaml.safe_load(fh) or []

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
