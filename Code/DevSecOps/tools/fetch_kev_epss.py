import argparse
import datetime as dt
import json
import sys
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CHUNK = 50


# Tải catalog CISA KEV và điểm EPSS của FIRST cho các CVE gặp trong findings,
# ghi kèm nguồn, thời điểm tải và catalogVersion để số liệu truy được nguồn gốc.
def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "devsecops-experiment"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def cves_in(paths):
    found = set()
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        items = data.get("findings", []) if isinstance(data, dict) else data
        for item in items:
            for value in (item.get("cve"), item.get("rule_id")):
                if isinstance(value, str) and value.upper().startswith("CVE-"):
                    found.add(value.upper())
    return sorted(found)


def kev_snapshot(catalog, downloaded_at):
    return {
        "title": catalog.get("title"),
        "source": KEV_URL,
        "catalogVersion": catalog.get("catalogVersion"),
        "dateReleased": catalog.get("dateReleased"),
        "count": catalog.get("count"),
        "downloaded_at": downloaded_at,
        # Giữ đủ danh sách CVE (gọn) để tra cả CVE của image trong E4.
        "vulnerabilities": [
            {"cveID": v.get("cveID"), "dateAdded": v.get("dateAdded")}
            for v in catalog.get("vulnerabilities", [])
        ],
    }


def epss_snapshot(cves, downloaded_at):
    scores = []
    for start in range(0, len(cves), CHUNK):
        chunk = cves[start:start + CHUNK]
        data = fetch_json(f"{EPSS_URL}?cve={','.join(chunk)}")
        for row in data.get("data", []):
            scores.append({
                "cve": row["cve"],
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            })
    return {
        "source": EPSS_URL,
        "downloaded_at": downloaded_at,
        "queried_cves": len(cves),
        "scores": sorted(scores, key=lambda r: r["cve"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", nargs="*", default=[], help="tệp findings JSON để lấy CVE")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    downloaded_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        kev = kev_snapshot(fetch_json(KEV_URL), downloaded_at)
        epss = epss_snapshot(cves_in(args.findings), downloaded_at)
    except (OSError, ValueError, KeyError) as exc:
        print(f"fetch_kev_epss thất bại: {exc}", file=sys.stderr)
        return 1

    (out_dir / "kev.json").write_text(json.dumps(kev, indent=2) + "\n", encoding="utf-8")
    (out_dir / "epss.json").write_text(json.dumps(epss, indent=2) + "\n", encoding="utf-8")
    print(f"KEV {kev['catalogVersion']}: {len(kev['vulnerabilities'])} CVE; "
          f"EPSS: {len(epss['scores'])}/{epss['queried_cves']} CVE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
