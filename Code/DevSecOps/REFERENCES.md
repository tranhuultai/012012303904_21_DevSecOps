# Tài liệu tham khảo và phạm vi chuẩn

Tài liệu này ghi lại nguồn chính thức dùng cho phần lý thuyết. Các liên hệ bên
dưới là ánh xạ chủ đề để định hướng policy; repo chưa tuyên bố chứng nhận tuân
thủ CSA CCM hoặc CIS Benchmark.

## Nguồn chính thức

1. Cloud Security Alliance, [Cloud Controls Matrix (CCM) v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1).
2. Center for Internet Security, [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) và [Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
3. FIRST, [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification.document).
4. FIRST, [EPSS](https://www.first.org/epss/) và [EPSS FAQ](https://www.first.org/epss/faq).
5. CISA, [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
6. SLSA, [Build requirements](https://slsa.dev/spec/v1.2/build-requirements) và [Provenance](https://slsa.dev/spec/v1.2/provenance).

## Ánh xạ phạm vi trong repo

| Thành phần trong repo | Chủ đề tham chiếu | Giới hạn |
|---|---|---|
| Terraform IAM, security group, S3, RDS | CSA CCM: quản trị định danh/quyền, bảo vệ dữ liệu và hạ tầng cloud; CIS AWS Foundations Benchmark | Chưa ghi control ID cụ thể; Terraform chỉ được quét, không apply |
| Kubernetes manifests | CIS Kubernetes Benchmark: quyền workload, đặc quyền container, giới hạn tài nguyên | Chỉ kiểm tra một tập nhỏ rule Checkov/Trivy, không phải đánh giá benchmark đầy đủ |
| Dockerfile và image | CIS Docker Benchmark và kiểm soát image trong chuỗi cung ứng | Chưa chạy CIS-CAT; policy hiện dùng Checkov/Trivy và kiểm tra Dockerfile |
| Cosign + GitHub artifact attestations + CycloneDX SBOM | Xác thực artifact, nguồn build và thành phần phụ thuộc | Provenance được tạo ở release job; CI run mới cần xác nhận quyền API/registry và attestation upload thành công |

CVSS biểu đạt mức độ nghiêm trọng kỹ thuật; EPSS là dự báo xác suất khai thác
trong 30 ngày; KEV ghi nhận CVE đã bị khai thác. Ba tín hiệu bổ sung cho nhau,
không nên xem điểm EPSS hoặc CVSS riêng lẻ là đánh giá rủi ro môi trường hoàn
chỉnh.
