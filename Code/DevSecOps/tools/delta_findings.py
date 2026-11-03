import argparse
import json
import sys
from pathlib import Path


# Chế độ delta của gate: giữ finding chưa có ở baseline (lần quét gần nhất trên main),
# so theo fingerprint ổn định tool + rule_id + tệp + resource, không dùng số dòng.
def stable_fingerprint(finding):
    location = finding.get("location") or {}
    return "|".join([
        str(finding.get("tool") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("file") or location.get("file") or ""),
        str(finding.get("resource") or location.get("resource") or ""),
    ])


def load_findings(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if "findings" not in data:
            raise ValueError(f"object thiếu khóa 'findings': {path}")
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError(f"findings phải là mảng: {path}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        current = load_findings(args.current)
        baseline = {stable_fingerprint(f) for f in load_findings(args.baseline)}
    except (OSError, ValueError) as exc:
        print(f"delta_findings thất bại: {exc}", file=sys.stderr)
        return 1

    new = [f for f in current if stable_fingerprint(f) not in baseline]
    Path(args.out).write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"delta: {len(new)}/{len(current)} finding mới so với baseline ({len(baseline)} fingerprint)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
