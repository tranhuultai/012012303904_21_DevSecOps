#!/usr/bin/env bash
# Cài công cụ quét bản ghim trên runner Linux, kiểm checksum theo tệp phát hành.
# Phiên bản lấy từ biến môi trường (TRIVY_VERSION, GITLEAKS_VERSION, ...), giống ci.yml.
# Dùng: install_scanners.sh trivy gitleaks conftest syft grype semgrep checkov
set -euo pipefail

tmp="${RUNNER_TEMP:-/tmp}"

fetch_tar() {
  local repo="$1" ver="$2" asset="$3" sums="$4" bin="$5"
  local base="https://github.com/${repo}/releases/download/v${ver}"
  local expected actual
  curl -fsSL --retry 3 -o "${tmp}/${asset}" "${base}/${asset}"
  curl -fsSL --retry 3 -o "${tmp}/${bin}.sums" "${base}/${sums}"
  expected="$(awk -v n="${asset}" '($2 == n || $2 == ("*" n)) {print $1; f = 1} END {if (!f) exit 1}' "${tmp}/${bin}.sums")"
  actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
  if [ "${expected}" != "${actual}" ]; then
    echo "checksum mismatch: ${asset}" >&2
    exit 1
  fi
  tar xzf "${tmp}/${asset}" -C "${tmp}" "${bin}"
  sudo install "${tmp}/${bin}" /usr/local/bin/
}

for tool in "$@"; do
  case "${tool}" in
    trivy) fetch_tar aquasecurity/trivy "${TRIVY_VERSION:?}" "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" trivy ;;
    gitleaks) fetch_tar gitleaks/gitleaks "${GITLEAKS_VERSION:?}" "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks ;;
    conftest) fetch_tar open-policy-agent/conftest "${CONFTEST_VERSION:?}" "conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" "checksums.txt" conftest ;;
    syft) fetch_tar anchore/syft "${SYFT_VERSION:?}" "syft_${SYFT_VERSION}_linux_amd64.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" syft ;;
    grype) fetch_tar anchore/grype "${GRYPE_VERSION:?}" "grype_${GRYPE_VERSION}_linux_amd64.tar.gz" "grype_${GRYPE_VERSION}_checksums.txt" grype ;;
    semgrep) python -m pip install --quiet "semgrep==${SEMGREP_VERSION:?}" ;;
    checkov) pipx install --quiet "checkov==${CHECKOV_VERSION:?}" ;;
    *) echo "không biết công cụ: ${tool}" >&2; exit 2 ;;
  esac
done
