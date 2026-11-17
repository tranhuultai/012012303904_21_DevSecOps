#!/usr/bin/env bash
# Tải một tệp phát hành trên GitHub.
# Dùng: download_release.sh <tệp đích> https://github.com/<chủ>/<repo>/releases/download/<tag>/<tên tệp>
#
# Có GH_TOKEN thì tải qua API bằng token của workflow: yêu cầu có xác thực được giới hạn tần suất
# cao hơn nhiều so với yêu cầu ẩn danh từ địa chỉ IP dùng chung của runner.
# Không được thì tải trực tiếp bằng curl có thử lại. Thất bại hẳn thì ghi mã HTTP thành annotation.
# Checksum vẫn do bước gọi kiểm như cũ.
set -euo pipefail

out="$1"
url="$2"
re='^https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^/]+)$'

if [[ -n "${GH_TOKEN:-}" && "${url}" =~ ${re} ]] && command -v gh >/dev/null 2>&1; then
  repo="${BASH_REMATCH[1]}"
  tag="${BASH_REMATCH[2]}"
  asset="${BASH_REMATCH[3]}"
  for attempt in 1 2 3; do
    if gh release download "${tag}" -R "${repo}" -p "${asset}" -O "${out}" --clobber; then
      exit 0
    fi
    sleep $((attempt * 5))
  done
  echo "::warning title=Tải công cụ::Tải qua API thất bại, chuyển sang tải trực tiếp ${url}"
fi

if curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o "${out}" "${url}"; then
  exit 0
fi
code="$(curl -sSL -o /dev/null -w '%{http_code} %{url_effective}' "${url}" || true)"
echo "::error title=Tải công cụ thất bại::HTTP ${code} (yêu cầu ${url})"
exit 1
