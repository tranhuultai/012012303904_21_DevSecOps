# Phiên bản công cụ và hành động (TOOL_VERSIONS)

Mọi công cụ bảo mật và GitHub Action dùng trong pipeline đều được **ghim phiên bản**;
binary bên ngoài được kiểm checksum theo tệp phát hành chính thức ngay khi cài (xem
`.github/workflows/ci.yml`). Bảng này là nguồn sự thật duy nhất về phiên bản.

Người chịu trách nhiệm cập nhật: Trần Hữu Tài (Tài) — mục 4.5 phân công.
Khi nâng phiên bản: cập nhật bảng này cùng env trong `ci.yml`, `experiments.yml`, `e3-timing.yml` trong một PR.

## 1. GitHub Actions (ghim SHA đầy đủ 40 ký tự)

| Action | Tag | Commit SHA | Dùng ở job |
|---|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | tất cả job |
| actions/setup-python | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | test, security-scan, gate |
| actions/cache | v5.0.5 | `27d5ce7f107fe9357f9df03efb73ab90386fccae` | e3-timing (cấu hình C3) |
| actions/upload-artifact | v7.0.0 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | scan, iac, image, gate, release |
| actions/download-artifact | v7.0.0 | `37930b1c2abaa49bbe596cd826c3c89aef350131` | gate |
| actions/attest | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` | release provenance |

Ghi chú: Trivy được gọi trực tiếp bằng CLI ghim phiên bản (không dùng trivy-action)
để toàn bộ công cụ quét đi qua một cơ chế kiểm checksum duy nhất.

## 2. Binary / CLI (ghim tag, kiểm checksum khi cài)

| Công cụ | Phiên bản | Nguồn phát hành | Cách kiểm chứng |
|---|---|---|---|
| Trivy | 0.76.1 | github.com/aquasecurity/trivy | sha256 theo `trivy_*_checksums.txt` |
| Syft | 1.54.1 | github.com/anchore/syft | sha256 theo `syft_*_checksums.txt` |
| Grype | 0.120.1 | github.com/anchore/grype | sha256 theo `grype_*_checksums.txt` |
| Checkov | 3.3.22 | PyPI (pipx) | ghim `==3.3.22` |
| Gitleaks | 8.30.1 | github.com/gitleaks/gitleaks | sha256 theo `gitleaks_*_checksums.txt` |
| Conftest (OPA 1.21.1) | 0.71.1 | github.com/open-policy-agent/conftest | sha256 theo `checksums.txt` |
| Semgrep | 1.183.0 | PyPI (pip) | ghim `==1.183.0` |
| Cosign | 3.1.3 | github.com/sigstore/cosign | sha256 theo `cosign_checksums.txt` |
| kind | 0.33.0 | github.com/kubernetes-sigs/kind | ghim tag + TLS (không có tệp checksums gộp) |

## 3. Môi trường runtime

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| Runner | ubuntu-24.04 | ghim trong `runs-on` |
| Python (mọi job) | 3.13.18 | `actions/setup-python`, ghim trong các workflow |
| Python (phát triển cục bộ) | 3.13 | thư viện ghim trong `requirements.txt` |
| jsonschema, PyYAML | 4.26.0, 6.0.3 | ghim trong workflow (gate, aggregate, e3-timing) |
| matplotlib | 3.11.2 | job test (test phân tích) |

Bộ luật Semgrep registry `p/python` tải lúc chạy, không ghim được phiên bản; kết quả `semgrep-registry`
có thể khác khi chạy lại.

## 4. Nguyên tắc cập nhật

1. Không dùng tag trôi (`@v4`, `@latest`) cho action; luôn kèm SHA đầy đủ.
2. Binary tải bằng HTTPS từ trang phát hành chính thức, kiểm `sha256sum -c` trước khi cài.
3. Mỗi lần đổi phiên bản phải chạy lại: `run_policy_tests.ps1`, `pytest`, E1–E4
   và ghi kết quả mới vào `tests/results/metrics/`.
