#!/usr/bin/env python3
"""Làm giàu findings đã chuẩn hóa bằng ngữ cảnh rủi ro cho Security Gate G2.

Với mỗi finding, bổ sung các trường mà gate_input.schema.json cho phép:
    - kev:              CVE nằm trong danh mục CISA KEV (tệp cisa_kev_subset.json).
    - epss:             điểm EPSS [0..1] từ tệp epss_subset.json; không có thì 0.0.
    - fix_available:    có bản vá hay chưa (trivy: FixedVersion; grype: fix.versions).
    - match_confidence: "high" khi rule_id/CVE khớp trực tiếp với luật chặn của G2
                        hoặc CVE khớp KEV/EPSS; ngược lại "low".
    - location:         {"file": ..., "resource": ...} đúng cấu trúc gate G2 mong đợi.

Đầu vào/đầu ra đều là mảng findings dạng schema finding.schema.json (mở rộng).
Không sửa trường gốc nào ngoài việc bổ sung; giữ nguyên thứ tự phần tử.

Dùng:
    python tools/enrich_findings.py \
        --findings reports/normalized_findings.json \
        --kev security/kev/cisa_kev_subset.json \
        --epss security/kev/epss_subset.json \
        --out reports/enriched_findings.json
"""

import argparse
import json
import sys
from pathlib import Path

# Trùng với iac_block_controls trong policy/g2/gate.rego: khớp trực tiếp => high.
IAC_BLOCK_CONTROLS = {
    "CKV_AWS_24", "CKV_AWS_25",
    "CKV_AWS_1", "CKV_AWS_49", "CKV_AWS_62", "CKV_AWS_63",
    "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56",
    "CKV_AWS_17", "CKV_AWS_16",
    "CKV_K8S_16", "CKV_K8S_14", "CKV_K8S_43",
    "KSV-0111", "KSV-0109",
    "CKV2_GHA_1", "CKV_GHA_2",
}

SECRET_CATEGORIES = {"secret"}
HIGH_CONFIDENCE_CATEGORIES = {"sast", "secret"}


def load_json(path):
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def load_kev_ids(kev_data):
    if isinstance(kev_data, dict):
        items = kev_data.get("vulnerabilities", [])
    else:
        items = kev_data
    return {
        str(item.get("cveID", "")).upper()
        for item in items
        if isinstance(item, dict) and item.get("cveID")
    }


def load_epss_map(epss_data):
    if isinstance(epss_data, dict):
        items = epss_data.get("scores", [])
    else:
        items = epss_data
    mapping = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cve", "")).upper()
        score = item.get("epss", 0.0)
        if cve and isinstance(score, (int, float)) and not isinstance(score, bool):
            mapping[cve] = float(min(max(score, 0.0), 1.0))
    return mapping


def finding_cve(finding):
    """CVE của finding: trường cve hoặc rule_id dạng CVE-...."""
    cve = finding.get("cve")
    if isinstance(cve, str) and cve.upper().startswith("CVE-"):
        return cve.upper()
    rule_id = str(finding.get("rule_id", "")).upper()
    if rule_id.startswith("CVE-"):
        return rule_id
    return None


def detect_fix_available(finding):
    """Suy luận có bản vá từ message đã chuẩn hóa hoặc trường gốc nếu có."""
    if "fix_available" in finding:
        return bool(finding["fix_available"])
    message = str(finding.get("message", ""))
    if "Fixed version:" in message:
        tail = message.split("Fixed version:", 1)[1].split(";", 1)[0].strip()
        return bool(tail) and tail.lower() not in {"none", "null", "n/a", ""}
    return False


def match_confidence(finding, kev_ids, epss_map):
    category = finding.get("category")
    rule_id = str(finding.get("rule_id", ""))
    cve = finding_cve(finding)
    if category in SECRET_CATEGORIES:
        return "high"
    if category in HIGH_CONFIDENCE_CATEGORIES:
        return "high"
    if rule_id in IAC_BLOCK_CONTROLS:
        return "high"
    if cve and (cve in kev_ids or cve in epss_map):
        return "high"
    return "low"


def enrich(finding, kev_ids, epss_map):
    out = dict(finding)
    cve = finding_cve(out)
    out["kev"] = bool(cve and cve in kev_ids)
    out["epss"] = round(epss_map.get(cve, 0.0), 4) if cve else 0.0
    out["fix_available"] = detect_fix_available(out)
    out["match_confidence"] = match_confidence(out, kev_ids, epss_map)

    file_path = out.get("file")
    location = {
        "file": file_path if isinstance(file_path, str) else "",
        "resource": str(out.get("resource", "")),
    }
    out["location"] = location
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Enrich normalized findings with KEV/EPSS/fix/confidence context."
    )
    parser.add_argument("--findings", required=True)
    parser.add_argument("--kev", required=True)
    parser.add_argument("--epss", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        findings = load_json(Path(args.findings))
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("Findings must be a JSON array.")

        kev_ids = load_kev_ids(load_json(Path(args.kev)))
        epss_map = load_epss_map(load_json(Path(args.epss)))

        enriched = [enrich(f, kev_ids, epss_map) for f in findings]

        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(enriched, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

        kev_hits = sum(1 for f in enriched if f["kev"])
        epss_hits = sum(1 for f in enriched if f["epss"] > 0)
        fixable = sum(1 for f in enriched if f["fix_available"])
        print(f"enriched: {len(enriched)} findings -> {out_path}")
        print(f"  kev=true: {kev_hits}, epss>0: {epss_hits}, fix_available: {fixable}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"enrich_findings failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
