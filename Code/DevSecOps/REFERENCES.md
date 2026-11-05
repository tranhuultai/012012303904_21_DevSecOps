# Tài liệu tham khảo và phạm vi chuẩn

Tài liệu này ghi lại nguồn chính thức cho phần lý thuyết và nêu rõ phạm vi ánh
xạ từng kiểm soát. Repo không tuyên bố chứng nhận tuân thủ CSA CCM hay CIS
Benchmark.

## Nguồn chính thức

1. Cloud Security Alliance, [Cloud Controls Matrix (CCM) v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) và [Implementation Guidelines](https://cloudsecurityalliance.org/artifacts/ccmv4-1-implementation-guidelines).
2. Center for Internet Security, [Amazon Web Services Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) và [Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
3. FIRST, [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification.document).
4. FIRST, [EPSS](https://www.first.org/epss/) và [EPSS FAQ](https://www.first.org/epss/faq).
5. CISA, [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
6. SLSA, [Build requirements](https://slsa.dev/spec/v1.2/build-requirements) và [Provenance](https://slsa.dev/spec/v1.2/provenance).

## Ánh xạ phạm vi trong repo

| Mẫu/kiểm soát trong repo | Ánh xạ tham chiếu | Kiểm tra được trong repo | Giới hạn |
|---|---|---|---|
| D16: SSH `22/tcp` mở từ `0.0.0.0/0`; `infra/security_groups.tf`; Checkov `CKV_AWS_24` | CIS AWS Foundations Benchmark 7.0.0, **6.3**: không mở cổng quản trị từ IPv4 toàn Internet; CSA CCM v4.1, miền **IVS** (Infrastructure & Virtualization Security) | Checkov quét Terraform và fixture D16 gieo cấu hình sai | Không bao phủ mọi cổng quản trị hay đánh giá tài khoản AWS đang chạy. Rà soát số hiệu CIS khi nâng phiên bản benchmark |
| D17: quyền IAM dạng wildcard; `infra/iam.tf`; Checkov `CKV_AWS_1` | CIS AWS Foundations Benchmark 7.0.0, **2.14**: không gắn policy toàn quyền `*:*`; CSA CCM v4.1 **IAM-05 Least Privilege** | Checkov quét cấu hình và fixture D17; policy mẫu hợp lệ chỉ cấp `s3:GetObject`/`s3:ListBucket` trên đúng bucket | Không chứng minh IAM runtime của tài khoản AWS; không phải đánh giá toàn bộ miền IAM |
| Quy trình kiểm tra thay đổi, test và gate trong `.github/workflows/ci.yml` | CSA CCM v4.1 **CCC-02 Quality Testing** và **CCC-06 Change Management Baseline** | Workflow có test, scan, policy gate, artifact và baseline commit để so sánh fixture | Ánh xạ quy trình này không phải chứng nhận CCM hoặc đánh giá hiệu quả tổ chức |
| S3, RDS và các mẫu IaC còn lại | CIS AWS Foundations/AWS service benchmarks và CSA CCM về dữ liệu, logging, hạ tầng | Checkov/Trivy kiểm tra một tập rule; D18–D20 là fixture; Terraform chỉ được quét, không apply | Chưa ánh xạ từng rule sang ID chuẩn. Không suy diễn kết quả scanner thành tuân thủ benchmark |
| Kubernetes manifests | CIS Kubernetes Benchmark: quyền workload, đặc quyền container, giới hạn tài nguyên | Checkov/Trivy kiểm tra một tập rule, có D21–D25 | Chưa cố định phiên bản benchmark và chưa chạy CIS-CAT; không phải đánh giá benchmark đầy đủ |
| Dockerfile và image | CIS Docker Benchmark và kiểm soát image trong chuỗi cung ứng | Checkov/Trivy và kiểm tra cấu hình Dockerfile; E4 có luồng so sánh image/SBOM | Chưa chạy CIS-CAT; số liệu, SBOM và báo cáo lỗ hổng E4 nằm trong `tests/results/raw/exp_20261103_41659076551/e4/` |
| Cosign, GitHub artifact attestations, CycloneDX SBOM | SLSA build provenance và kiểm soát thành phần chuỗi cung ứng | Release job tạo provenance, ký image, phát hành SBOM; deploy-smoke xác minh chữ ký | Việc tạo provenance không đồng nghĩa provenance đã được xác minh độc lập |

Mã CIS/CSA là tham chiếu cho các fixture và quy trình nêu trong bảng. Chúng
không khẳng định toàn repository hoặc môi trường cloud đã tuân thủ benchmark.
Các mã CIS ghi theo bản 7.0.0 để đối chiếu cụ thể. Tại thời điểm cập nhật,
[CIS đang liệt kê bản AWS Foundations 7.1.0](https://www.cisecurity.org/benchmark/amazon_web_services);
hãy kiểm tra lại số hiệu với bản 7.1.0 trước khi chốt báo cáo.

CVSS biểu đạt mức độ nghiêm trọng kỹ thuật; EPSS là dự báo xác suất khai thác
trong 30 ngày; KEV ghi nhận CVE đã bị khai thác. Ba tín hiệu bổ sung cho nhau,
không nên xem điểm EPSS hoặc CVSS riêng lẻ là đánh giá rủi ro môi trường hoàn
chỉnh.
