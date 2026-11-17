import argparse
import csv
import gzip
import json
import statistics
import sys
from pathlib import Path

IMAGES = (("vuln", "lab/docker/Dockerfile.vuln"), ("fixed", "Dockerfile"))
RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# E4: so image trước (Dockerfile.vuln) và sau khắc phục (Dockerfile) từ báo cáo thật:
# kích thước, thời gian build, số gói SBOM, CVE theo mức và theo có/chưa có bản vá, CVE thuộc KEV.
def load(path):
    path = Path(path)
    if not path.exists():  # bản đã commit trong results/raw được nén gzip
        return json.loads(gzip.decompress(path.with_name(path.name + ".gz").read_bytes()))
    return json.loads(path.read_text(encoding="utf-8"))


def trivy_cves(report):
    """Gộp bản ghi Trivy (gói x CVE) thành CVE duy nhất: mức cao nhất, có bản vá nếu có gói vá được."""
    cves = {}
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID")
            if not cve:
                continue
            sev = str(vuln.get("Severity") or "UNKNOWN").upper()
            fixed = bool(vuln.get("FixedVersion"))
            prev = cves.get(cve, {"severity": "UNKNOWN", "fixable": False, "records": 0})
            cves[cve] = {
                "severity": sev if RANK.get(sev, 0) > RANK.get(prev["severity"], 0) else prev["severity"],
                "fixable": prev["fixable"] or fixed,
                "records": prev["records"] + 1,
            }
    return cves


def summarize(image, dockerfile, src, kev_ids):
    cves = trivy_cves(load(src / f"trivy_{image}.json"))
    syft = load(src / f"syft_{image}.json")
    grype = load(src / f"grype_{image}.json")
    builds = [float(r["seconds"]) for r in read_tsv(src / "builds.tsv") if r["image"] == image]
    size = next(int(r["bytes"]) for r in read_tsv(src / "sizes.tsv") if r["image"] == image)
    by_sev = {s: sum(1 for c in cves.values() if c["severity"] == s) for s in RANK}
    return {
        "image": image,
        "dockerfile": dockerfile,
        "size_bytes": size,
        "size_mb": round(size / 1_000_000, 1),
        "build_seconds_median": round(statistics.median(builds), 1) if builds else "",
        "build_runs": len(builds),
        "sbom_packages": len(syft.get("artifacts") or []),
        "trivy_records": sum(c["records"] for c in cves.values()),
        "unique_cves": len(cves),
        "critical": by_sev["CRITICAL"],
        "high": by_sev["HIGH"],
        "medium": by_sev["MEDIUM"],
        "low": by_sev["LOW"],
        "unknown": by_sev["UNKNOWN"],
        "fixable_cves": sum(1 for c in cves.values() if c["fixable"]),
        "unfixed_cves": sum(1 for c in cves.values() if not c["fixable"]),
        "crit_high_fixable": sum(
            1 for c in cves.values() if c["fixable"] and c["severity"] in ("CRITICAL", "HIGH")
        ),
        "kev_cves": sum(1 for cve in cves if cve in kev_ids),
        "grype_matches": len(grype.get("matches") or []),
    }


def read_tsv(path):
    with Path(path).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="thư mục artifact exp-e4")
    parser.add_argument("--kev", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    src = Path(args.input)
    kev_ids = {v["cveID"] for v in load(args.kev).get("vulnerabilities", [])}
    rows = [summarize(image, dockerfile, src, kev_ids) for image, dockerfile in IMAGES]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "e4_images.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
