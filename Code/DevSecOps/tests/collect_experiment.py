import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
GROUND_TRUTH = PROJECT_DIR / "ground_truth" / "ground_truth.csv"


# Gom kết quả quét của từng mẫu (artifact exp-<ID>) thành bảng finding, bảng thời gian
# và bảng mẫu; đánh dấu finding đã có ở baseline theo fingerprint ổn định.
def stable_fingerprint(finding):
    """tool + rule_id + tệp + resource; không dùng số dòng để patch dời dòng không tạo finding mới."""
    location = finding.get("location") or {}
    resource = finding.get("resource") or location.get("resource") or ""
    return "|".join([
        str(finding.get("tool") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("file") or location.get("file") or ""),
        str(resource),
    ])


def read_json(path, default=None):
    path = Path(path)
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_timings(path):
    path = Path(path)
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def load_samples(input_dir):
    samples = {}
    for sample_dir in sorted(Path(input_dir).glob("exp-*")):
        meta = read_json(sample_dir / "meta.json")
        if not meta or meta.get("kind") == "e4":
            continue
        samples[meta["change_id"]] = {
            "meta": meta,
            "findings": read_json(sample_dir / "normalized_findings.json"),
            "timings": read_timings(sample_dir / "timings.tsv"),
            "versions": read_json(sample_dir / "versions.json", {}),
        }
    return samples


def expected_ids():
    with GROUND_TRUTH.open(encoding="utf-8") as fh:
        return ["BASE"] + [row["id"] for row in csv.DictReader(fh)]


def trivy_db(versions):
    trivy = versions.get("trivy") if isinstance(versions, dict) else None
    if not isinstance(trivy, dict):
        return ""
    return (trivy.get("VulnerabilityDB") or {}).get("UpdatedAt", "")


def tool_signature(versions):
    trivy = versions.get("trivy") if isinstance(versions, dict) else None
    trivy_version = trivy.get("Version", "") if isinstance(trivy, dict) else str(trivy)
    return (
        versions.get("semgrep", ""), versions.get("gitleaks", ""), versions.get("checkov", ""),
        versions.get("conftest", ""), trivy_version,
    )


def write_csv(path, header, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="thư mục chứa các artifact exp-<ID>")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    samples = load_samples(args.input)
    if "BASE" not in samples or samples["BASE"]["findings"] is None:
        print("thiếu kết quả baseline (BASE)", file=sys.stderr)
        return 2
    base = {stable_fingerprint(f) for f in samples["BASE"]["findings"]}

    finding_rows, timing_rows, sample_rows = [], [], []
    for change_id in expected_ids():
        sample = samples.get(change_id)
        if not sample or sample["findings"] is None:
            sample_rows.append([change_id, "missing", "", "", "", "", "", ""])
            continue
        meta, findings = sample["meta"], sample["findings"]
        new = 0
        for f in findings:
            fp = stable_fingerprint(f)
            in_base = fp in base
            new += not in_base
            finding_rows.append([
                change_id, f.get("tool"), f.get("category"), f.get("rule_id"), f.get("severity"),
                f.get("file") or "", f.get("resource") or "", f.get("line_start") or "",
                f.get("cve") or "", fp, int(in_base),
            ])
        for t in sample["timings"]:
            seconds = float(t["finished"]) - float(t["started"])
            timing_rows.append([change_id, t["step"], f"{seconds:.3f}", t["exit_code"],
                                meta.get("run_id"), meta.get("job_url", "")])
        sample_rows.append([change_id, "complete", meta.get("commit"), meta.get("run_id"),
                            meta.get("run_url"), len(findings), new, trivy_db(sample["versions"])])

    write_csv(out / "findings_all.csv",
              ["change_id", "tool", "category", "rule_id", "severity", "file", "resource",
               "line_start", "cve", "stable_fingerprint", "in_baseline"], finding_rows)
    write_csv(out / "scan_runs.csv",
              ["change_id", "step", "seconds", "exit_code", "run_id", "job_url"], timing_rows)
    write_csv(out / "samples.csv",
              ["change_id", "status", "commit", "run_id", "run_url", "n_findings", "n_new",
               "trivy_db_updated_at"], sample_rows)

    present = [s for s in samples.values() if s["findings"] is not None]
    consistency = {
        "samples_expected": len(expected_ids()),
        "samples_complete": sum(1 for r in sample_rows if r[1] == "complete"),
        "tool_versions_equal": len({tool_signature(s["versions"]) for s in present}) == 1,
        "trivy_db_snapshots": sorted({trivy_db(s["versions"]) for s in present}),
        "commits": sorted({s["meta"].get("commit", "") for s in present}),
    }
    (out / "consistency.json").write_text(json.dumps(consistency, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(consistency, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
