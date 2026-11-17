#!/usr/bin/env bash
# Quét đủ 5 lớp trên cây làm việc (đã áp patch); ghi báo cáo thô, timings.tsv, versions.json.
# Dùng (đứng ở Code/DevSecOps): tests/run_scans.sh <out_dir> [--image]
set -uo pipefail

out="${1:?thiếu out_dir}"
with_image="${2:-}"
root="$(git rev-parse --show-toplevel)"
layers=" ${LAYERS:-sast secret sca iac image} "
mkdir -p "${out}"
timings="${out}/timings.tsv"
printf 'step\tstarted\tfinished\texit_code\n' > "${timings}"

has() { case "${layers}" in *" $1 "*) return 0 ;; esac; return 1; }

step() {
  local name="$1" start end status
  shift
  start="$(date -u +%s.%N)"
  "$@" > "${out}/${name}.log" 2>&1
  status=$?
  end="$(date -u +%s.%N)"
  printf '%s\t%s\t%s\t%s\n' "${name}" "${start}" "${end}" "${status}" >> "${timings}"
}

# SAST: chạy tách hai bộ luật để so luật tự viết với bộ luật registry.
if has sast; then
step semgrep_custom semgrep scan --config rules/semgrep --metrics=off --json --output "${out}/semgrep.json" src tools
step semgrep_registry semgrep scan --config "${SEMGREP_REGISTRY_RULESET:-p/python}" --metrics=off --json --output "${out}/semgrep_registry.json" src tools
fi
# Secret: quét cây làm việc để thấy thay đổi chưa commit.
has secret && step gitleaks gitleaks dir "${root}" --config "${root}/.gitleaks.toml" --report-format json --report-path "${out}/gitleaks.json" --exit-code 0
# SCA
has sca && step trivy_fs trivy fs --scanners vuln --format json --output "${out}/trivy.json" --exit-code 0 --ignore-unfixed .
# IaC: gọi Checkov riêng từng framework rồi gộp, tránh trường hợp gọi gộp bỏ sót Dockerfile.
if has iac; then
step checkov_iac sh -c "checkov -d infra -d deploy --framework terraform kubernetes --compact --soft-fail -o json > '${out}/checkov_iac.json'"
step checkov_docker sh -c "checkov -f Dockerfile --framework dockerfile --compact --soft-fail -o json > '${out}/checkov_docker.json'"
step checkov_gha sh -c "checkov -d lab/workflows-vuln --framework github_actions --compact --soft-fail -o json > '${out}/checkov_gha.json'"
step trivy_config trivy config --format json --output "${out}/trivy_config.json" --exit-code 0 --skip-dirs lab .
# Workflow: luật Conftest tự viết (Conftest thoát 1 khi có deny, vẫn ghi đủ báo cáo).
step conftest_wf sh -c "conftest test -p rules/conftest lab/workflows-vuln/.github/workflows/ci-vuln.yml -o json > '${out}/conftest_wf.json'; test -s '${out}/conftest_wf.json'"
jq -s 'map(if type == "array" then .[] else . end)' \
  "${out}/checkov_iac.json" "${out}/checkov_docker.json" "${out}/checkov_gha.json" > "${out}/checkov.json"
fi

if [ "${with_image}" = "--image" ] && has image; then
  step image_build docker build -q -f Dockerfile -t exp-image:scan .
  step trivy_image trivy image --format json --output "${out}/trivy_image.json" --exit-code 0 exp-image:scan
fi

python - "${out}" <<'PY'
import json
import subprocess
import sys


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error: {exc}"


trivy = run("trivy", "version", "--format", "json")
versions = {
    "semgrep": run("semgrep", "--version"),
    "gitleaks": run("gitleaks", "version"),
    "checkov": run("checkov", "--version"),
    "conftest": run("conftest", "--version"),
    "trivy": json.loads(trivy) if trivy.startswith("{") else trivy,
}
with open(f"{sys.argv[1]}/versions.json", "w", encoding="utf-8") as fh:
    json.dump(versions, fh, indent=2)
PY
