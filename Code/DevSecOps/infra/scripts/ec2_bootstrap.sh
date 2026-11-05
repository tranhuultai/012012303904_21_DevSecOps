#!/usr/bin/env bash
# Script khởi động của EC2 (được nhúng vào user_data trong compute.tf).
# Workflow iac-validate chạy đúng script này trên máy Ubuntu 24.04 của GitHub để thử trước
# khi có tài khoản AWS.
#
# Các bước: cài Docker nếu thiếu -> cài cosign bản ghim, kiểm checksum -> kiểm chữ ký image
# (đúng danh tính workflow của repo) -> chạy container với thiết lập giống manifest Kubernetes
# -> chờ /health. Chữ ký sai hoặc chưa ký thì dừng, không chạy container.
#
# Biến bắt buộc: APP_IMAGE (ghi theo digest), SIGNER_IDENTITY_REGEXP.
# Biến tùy chọn: APP_PORT (mặc định 8000). Cần chạy bằng root.
set -euo pipefail

: "${APP_IMAGE:?Thiếu APP_IMAGE}"
: "${SIGNER_IDENTITY_REGEXP:?Thiếu SIGNER_IDENTITY_REGEXP}"
APP_PORT="${APP_PORT:-8000}"
COSIGN_VERSION="3.1.3"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
CONTAINER="devsecops-app"

case "${APP_IMAGE}" in
  *@sha256:*) ;;
  *) echo "APP_IMAGE phải ghi theo digest (@sha256:...)" >&2; exit 1 ;;
esac

# 1. Docker
if ! command -v docker >/dev/null 2>&1; then
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io curl
  systemctl enable --now docker
fi

# 2. Cosign bản ghim, kiểm checksum theo tệp phát hành
if ! command -v cosign >/dev/null 2>&1 || ! cosign version 2>/dev/null | grep -q "v${COSIGN_VERSION}"; then
  tmp="$(mktemp -d)"
  base="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}"
  curl -fsSL -o "${tmp}/cosign-linux-amd64" "${base}/cosign-linux-amd64"
  curl -fsSL -o "${tmp}/cosign_checksums.txt" "${base}/cosign_checksums.txt"
  (cd "${tmp}" && grep "  cosign-linux-amd64$" cosign_checksums.txt | sha256sum -c -)
  install -m 0755 "${tmp}/cosign-linux-amd64" /usr/local/bin/cosign
  rm -rf "${tmp}"
fi

# 3. Kiểm chữ ký
cosign verify \
  --certificate-identity-regexp "${SIGNER_IDENTITY_REGEXP}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${APP_IMAGE}" > /dev/null
echo "Chữ ký hợp lệ: ${APP_IMAGE}"

# 4. Chạy container: user không phải root, hệ thống tệp chỉ đọc, bỏ mọi capability,
#    cấm leo thang đặc quyền, giới hạn CPU/RAM như deploy/deployment.yaml
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" --restart unless-stopped \
  --user 10001:10001 --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 128m --cpus 0.25 \
  -p "${APP_PORT}:8000" "${APP_IMAGE}"

# 5. Chờ ứng dụng trả lời /health
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/health"; then
    echo
    echo "Ứng dụng sẵn sàng trên cổng ${APP_PORT}"
    exit 0
  fi
  sleep 2
done
echo "Ứng dụng không trả lời /health" >&2
docker logs "${CONTAINER}" >&2 || true
exit 1
