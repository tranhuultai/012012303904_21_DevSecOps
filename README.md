# Đề tài 21 – DevSecOps

**Tên đề tài:** Xây dựng đường ống DevSecOps phát hiện cấu hình sai và lỗ hổng trước triển khai

## Giới thiệu

Đề tài xây dựng một pipeline DevSecOps trên GitHub Actions nhằm phát hiện cấu hình sai và lỗ hổng trước khi triển khai.

Pipeline gồm 5 lớp kiểm tra:

- SAST
- Secret scanning
- SCA
- IaC scanning
- Container image scanning

Kết quả từ các công cụ được chuẩn hóa và đưa vào Security Gate. Gate quyết định `BLOCK`, `WARN` hoặc `INFO` theo các chính sách G0, G1 và G2.

## Công cụ

| Thành phần | Công cụ |
| --- | --- |
| CI/CD | GitHub Actions |
| SAST | Semgrep |
| Secret scanning | Gitleaks |
| SCA | Trivy, Grype |
| IaC scanning | Checkov, Trivy |
| Container image | Trivy, Syft, Grype |
| Policy | Conftest / Rego |
| Image signing | Cosign |
| Deploy test | kind |

## Thực nghiệm

Bộ dữ liệu thực nghiệm gồm:

- 28 lỗi gieo cài
- 8 mẫu đối chứng
- 10 thay đổi sạch

Các thực nghiệm:

- **E1:** Đánh giá khả năng phát hiện
- **E2:** So sánh chính sách G0, G1 và G2
- **E3:** Đánh giá thời gian pipeline
- **E4:** Đánh giá ảnh hưởng của việc khắc phục đến image và SBOM

## Cấu trúc repository

```text
012012303904_21_DevSecOps/
├── .github/
│   ├── workflows/
│   │   └── ci.yml
│   ├── CODEOWNERS
│   └── pull_request_template.md
│
├── Code/
│   └── DevSecOpsGate/
│       ├── src/
│       │   └── test/
│       ├── infra/
│       ├── deploy/
│       ├── Dockerfile
│       ├── Dockerfile.vuln
│       ├── .dockerignore
│       ├── lab/
│       │   └── workflows-vuln/
│       ├── rules/
│       │   └── semgrep/
│       ├── tools/
│       │   └── test/
│       ├── schemas/
│       ├── policy/
│       │   ├── g0/
│       │   ├── g1/
│       │   └── g2/
│       ├── security/
│       ├── ground_truth/
│       │   └── patches/
│       └── tests/
│           ├── README.md
│           ├── make_variants.sh
│           ├── eval_policies.py
│           ├── collect_timings.py
│           ├── analysis.ipynb
│           └── results/
│               ├── raw/
│               ├── runs.csv
│               ├── findings.csv
│               ├── decisions.csv
│               ├── triage.csv
│               └── metrics/
│
├── DOCX/
├── PPTX/
├── Extra/
├── README.md
├── requirements.txt
└── .gitignore
```

## Tài liệu

- Báo cáo: `DOCX/`
- Slide: `PPTX/`
- Tài liệu bổ sung và phiên bản công cụ: `Extra/`
- Dữ liệu và mã phục vụ thực nghiệm: `Code/DevSecOpsGate/tests/`
