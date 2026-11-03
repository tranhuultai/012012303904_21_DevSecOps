#!/usr/bin/env bash
# Gate G2 trong phép đo E3: chuẩn hóa báo cáo có sẵn, làm giàu bằng snapshot KEV/EPSS, chấm bằng Conftest.
# Dùng (đứng ở Code/DevSecOps): tests/e3_gate.sh <reports_dir>
set -euo pipefail

r="${1:?thiếu reports_dir}"
args=()
for pair in semgrep:semgrep.json semgrep-registry:semgrep_registry.json gitleaks:gitleaks.json \
  trivy:trivy.json checkov:checkov.json trivy-config:trivy_config.json trivy-image:trivy_image.json \
  conftest-workflow:conftest_wf.json; do
  file="${r}/${pair#*:}"
  if [ -s "${file}" ]; then args+=("--${pair%%:*}" "${file}"); fi
done

python tools/test/normalize_findings.py "${args[@]}" --output "${r}/normalized_findings.json"
python tools/enrich_findings.py --findings "${r}/normalized_findings.json" \
  --kev security/kev/kev_snapshot.json --epss security/kev/epss_snapshot.json --out "${r}/enriched_findings.json"
python tools/gate_input.py --findings "${r}/enriched_findings.json" --exceptions security/exceptions.yaml \
  --today "$(date -u +%F)" --policy g2 --out "${r}/gate_input.json"
conftest test -p policy/g2 "${r}/gate_input.json" -o json > "${r}/gate_result.json" || true
