import argparse
import json
import os
import sys

import yaml


# Gộp findings đã chuẩn hóa, ngoại lệ và ngữ cảnh thành gate_input.json cho Conftest.
def load_findings(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    # Fail-closed: object phải có khóa "findings"; thiếu thì báo lỗi, không coi là sạch.
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    raise SystemExit(f"findings không hợp lệ: cần mảng hoặc object có khóa 'findings' ({path})")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--findings", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", required=True)
    p.add_argument("--policy", required=True, choices=["g0", "g1", "g2"])
    p.add_argument("--out", required=True)
    a = p.parse_args()

    findings = load_findings(a.findings)

    with open(a.exceptions, encoding="utf-8") as fh:
        exceptions = yaml.safe_load(fh) or []

    gate_input = {
        "findings": findings,
        "exceptions": exceptions,
        "context": {"today": a.today, "policy": a.policy},
    }

    # Ghi qua tệp tạm rồi thay thế để không để lại tệp hỏng; date -> chuỗi ISO.
    tmp = f"{a.out}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(gate_input, fh, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, a.out)
    print(f"gate_input: {len(findings)} findings, {len(exceptions)} exceptions -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
