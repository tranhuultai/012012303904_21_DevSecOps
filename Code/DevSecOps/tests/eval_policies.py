import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema
import yaml

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR / "tools"))
sys.path.insert(0, str(PROJECT_DIR / "tests"))

import enrich_findings as ef  # noqa: E402
from collect_experiment import expected_ids, load_samples, stable_fingerprint  # noqa: E402

POLICIES = ("g0", "g1", "g2")
MODES = ("full", "delta")


# Chấm offline cùng một bộ findings của từng mẫu bằng Conftest thật với G0/G1/G2,
# ở chế độ full (mọi finding) và delta (chỉ finding mới so với baseline).
def change_types():
    with (PROJECT_DIR / "ground_truth" / "ground_truth.csv").open(encoding="utf-8") as fh:
        types = {row["id"]: row["type"] for row in csv.DictReader(fh)}
    types["BASE"] = "baseline"
    return types


def run_conftest(policy_dir, gate_input):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(gate_input, fh)
        path = fh.name
    try:
        result = subprocess.run(
            ["conftest", "test", "-p", str(policy_dir), path, "-o", "json"],
            capture_output=True, encoding="utf-8", check=False,
        )
    finally:
        Path(path).unlink(missing_ok=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"conftest lỗi ({result.returncode}): {result.stderr[-300:]}")
    data = json.loads(result.stdout)
    deny = sum(len(r.get("failures") or []) for r in data)
    warn = sum(len(r.get("warnings") or []) for r in data)
    return deny, warn


def decide(deny, warn):
    return "BLOCK" if deny else ("WARN" if warn else "PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--kev", required=True)
    parser.add_argument("--epss", required=True)
    parser.add_argument("--today", required=True, help="ngày chấm (YYYY-MM-DD), ghi vào context")
    parser.add_argument("--policy-dir", default=str(PROJECT_DIR / "policy"))
    parser.add_argument("--exceptions", default=str(PROJECT_DIR / "security" / "exceptions.yaml"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    samples = load_samples(args.input)
    if "BASE" not in samples:
        print("thiếu baseline", file=sys.stderr)
        return 2
    kev_ids = ef.load_kev_ids(json.loads(Path(args.kev).read_text(encoding="utf-8")))
    epss_map = ef.load_epss_map(json.loads(Path(args.epss).read_text(encoding="utf-8")))
    exceptions = yaml.safe_load(Path(args.exceptions).read_text(encoding="utf-8")) or []
    schema = json.loads((PROJECT_DIR / "schemas" / "gate_input.schema.json").read_text(encoding="utf-8"))
    base = {stable_fingerprint(f) for f in samples["BASE"]["findings"] or []}
    types = change_types()

    rows = []
    for change_id in expected_ids():
        sample = samples.get(change_id)
        if not sample or sample["findings"] is None:
            continue
        enriched = [ef.enrich(f, kev_ids, epss_map) for f in sample["findings"]]
        for mode in MODES:
            subset = enriched if mode == "full" else [
                f for f in enriched if stable_fingerprint(f) not in base
            ]
            for policy in POLICIES:
                gate_input = {
                    "findings": subset,
                    "exceptions": exceptions,
                    "context": {"today": args.today, "policy": policy},
                }
                jsonschema.validate(gate_input, schema)
                deny, warn = run_conftest(Path(args.policy_dir) / policy, gate_input)
                rows.append([change_id, types.get(change_id, ""), policy, mode,
                             decide(deny, warn), deny, warn, len(subset)])

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "decisions.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["change_id", "type", "policy", "mode", "decision", "deny_count",
                         "warn_count", "n_findings"])
        writer.writerows(rows)
    print(f"decisions.csv: {len(rows)} dòng")
    return 0


if __name__ == "__main__":
    sys.exit(main())
