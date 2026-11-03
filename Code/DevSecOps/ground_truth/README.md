# Bảng ánh xạ lỗi thực nghiệm (Ground Truth & CWE/CVE Mapping)

Tài liệu này mô tả chi tiết bộ dữ liệu chuẩn (Ground Truth) phục vụ các thực nghiệm **E1** (Đánh giá khả năng phát hiện lỗi) và **E2** (So sánh hiệu quả chính sách Security Gate G0, G1, G2).

## Người phụ trách: Hoàng Gia Long (Long - gialong611)

---

## 1. Tổng quan bộ dữ liệu
Bộ dữ liệu chuẩn gồm **46 mẫu** được phân định chặt chẽ:
- **28 lỗi gieo cài (Defects D01–D28):** Bao phủ 5 lớp quét bảo mật (SAST, Secret, SCA, IaC/K8s, Workflow CI).
- **8 mẫu đối chứng (Negative Controls N01–N08):** Các đoạn mã và cấu hình an toàn nhưng có dạng gần giống lỗi (đo nguy cơ báo nhầm - False Positive).
- **10 thay đổi sạch (Clean Changes C01–C10):** Các thay đổi thông thường trong dự án như sửa docstring, thêm test, sửa annotation (đo tỷ lệ chặn nhầm - False Block Rate).

---

## 2. Bảng ánh xạ chi tiết 28 lỗi gieo cài (D01–D28)

> CVSS v3.1 lấy từ NVD, chỉ cho CVE. KEV theo catalog CISA `2026.10.30`, EPSS theo FIRST ngày 02/11/2026 (`security/kev/`). Rule ID chấp nhận khi chấm E1 nằm ở cột `accepted_rule_ids` của `ground_truth.csv`, lấy từ output thật của đúng phiên bản công cụ trong CI qua hai lần chạy hiệu chỉnh trước khi đóng băng `gt-v1`.

| ID | Lớp quét | Tệp vi phạm | Công cụ | Rule ID / CVE ID | Mã CWE | CVSS v3.1 (NVD, chỉ CVE) | KEV (tập con đã ghim) | EPSS (snapshot đã ghim) | G0 | G1 | G2 | Lý do phân tầng G2 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **D01** | SAST | `src/app/main.py` | Semgrep | `python.sqli.concatenation` | CWE-89 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | SAST High/Critical (nguy cơ chiếm quyền DB) |
| **D02** | SAST | `src/app/main.py` | Semgrep | `python.secrets.hardcoded` | CWE-798 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Lộ mật khẩu cứng trong mã nguồn |
| **D03** | SAST | `src/app/main.py` | Semgrep | `python.exec.command-injection` | CWE-78 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Command Injection cho phép RCE |
| **D04** | SAST | `src/app/main.py` | Semgrep | `python.file.path-traversal` | CWE-22 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | WARN | Mức Medium, hạ xuống WARN tránh nghẽn |
| **D05** | SAST | `src/app/main.py` | Semgrep | `python.pickle.insecure-deserialization` | CWE-502 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Deserialization pickle dẫn tới RCE |
| **D06** | SAST | `src/app/main.py` | Semgrep | `python.crypto.weak-hash-md5` | CWE-328 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | WARN | Thuật toán băm yếu mức Medium, cảnh báo |
| **D07** | Secret | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Gitleaks | `generic-api-key` | CWE-798 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | Secret luôn BLOCK (không cho phép ngoại lệ) |
| **D08** | Secret | `src/app/main.py` | Gitleaks | `generic-secret` | CWE-798 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Secret luôn BLOCK (không cho phép ngoại lệ) |
| **D09** | SCA | `src/requirements.txt` | Trivy | `CVE-2024-35195` (requests 2.31.0) | CWE-670 | 5.6 (Medium) | Không (catalog 2026.10.30) | 0,0034 | PASS | BLOCK | WARN | Mức Medium có bản vá: cảnh báo |
| **D10** | SCA | `src/requirements.txt` | Trivy | `CVE-2023-45803` (urllib3 2.0.6) | CWE-200 | 4.2 (Medium) | Không (catalog 2026.10.30) | 0,00593 | PASS | BLOCK | WARN | Mức Medium có bản vá: cảnh báo |
| **D11** | SCA | `src/requirements.txt` | Trivy | `CVE-2024-24762` (python-multipart 0.0.6) | CWE-1333 | 7.5 (High) | Không (catalog 2026.10.30) | 0,01523 | PASS | BLOCK | BLOCK | Mức High, có bản sửa (0.0.7), khớp tin cậy cao |
| **D12** | Image | `Code/DevSecOps/Dockerfile` | Trivy image | CVE mới của image (base đầy đủ thay bản slim) | CWE-1395 | theo từng CVE | theo catalog | theo từng CVE | PASS | BLOCK | BLOCK | Base đầy đủ thêm hàng nghìn gói; không có luật cấu hình nào bắt, chỉ đo được qua quét image |
| **D13** | Image | `Code/DevSecOps/Dockerfile` | Checkov | `CKV_DOCKER_3` | CWE-250 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Container chạy dưới quyền root |
| **D14** | Image | `Code/DevSecOps/Dockerfile` | Checkov | `CKV_DOCKER_4` | CWE-829 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Lệnh ADD tải file từ URL từ xa không xác thực |
| **D15** | Image | `Code/DevSecOps/Dockerfile` | Checkov | `CKV_DOCKER_1` | CWE-284 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | Cài sshd và mở cổng 22 trong container |
| **D16** | IaC | `infra/security_groups.tf` | Checkov | `CKV_AWS_24` | CWE-284 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Khóa kiểm soát cao: Mở SSH 0.0.0.0/0 ra Internet |
| **D17** | IaC | `infra/iam.tf` | Checkov | `CKV_AWS_1` | CWE-732 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Khóa kiểm soát cao: Wildcard Action và Resource `*` |
| **D18** | IaC | `infra/s3.tf` | Checkov | `CKV_AWS_53` | CWE-284 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Khóa kiểm soát cao: Tắt Public Access Block S3 |
| **D19** | IaC | `infra/rds.tf` | Checkov | `CKV_AWS_17` | CWE-284 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Khóa kiểm soát cao: Cơ sở dữ liệu RDS public |
| **D20** | IaC | `infra/s3.tf` | Checkov | `CKV_AWS_21` | CWE-16 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | WARN | Thiếu versioning/logging S3: mức Medium, WARN |
| **D21** | K8s | `deploy/deployment.yaml` | Checkov | `CKV_K8S_16` | CWE-250 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | Khóa kiểm soát cao: Container chạy privileged |
| **D22** | K8s | `deploy/deployment.yaml` | Checkov | `CKV_K8S_11` | CWE-400 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | WARN | Không đặt giới hạn tài nguyên: Medium, WARN |
| **D23** | K8s | `deploy/deployment.yaml` | Checkov, Trivy | `CKV_K8S_14`, `CKV_K8S_43`, `KSV-0013` | CWE-829 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | Tag `:latest` không bất biến; G2 chặn `CKV_K8S_14` như `CKV_DOCKER_7` |
| **D24** | K8s | `deploy/serviceaccount.yaml` | Trivy | `KSV-0111` | CWE-269 | N/A (rule, không phải CVE) | N/A | — | PASS | BLOCK | BLOCK | ServiceAccount gán ClusterRole `cluster-admin` |
| **D25** | K8s | `deploy/deployment.yaml` | Trivy | `KSV-0109` | CWE-522 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | Mật khẩu lưu dạng plaintext trong ConfigMap |
| **D26** | CI | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Checkov, Conftest | `CKV2_GHA_1`, `GHA-WRITE-ALL` | CWE-732 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | GITHUB_TOKEN cấp `write-all` |
| **D27** | CI | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Checkov, Conftest | `CKV_GHA_2`, `GHA-SCRIPT-INJECTION` | CWE-78 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | BLOCK | Script injection trong `run:` |
| **D28** | CI | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Conftest | `GHA-UNPINNED-ACTION` | CWE-829 | N/A (rule, không phải CVE) | N/A | N/A | PASS | BLOCK | WARN | Action tham chiếu tag thay vì SHA; Checkov bản mở không có luật này |

---

## 3. Bảng 8 mẫu đối chứng (Negative Controls N01–N08)

| ID | Lớp kiểm tra | Tệp áp dụng | Mô tả đoạn mã/cấu hình đối chứng | Lỗi đối chứng | Kết quả kỳ vọng |
|---|---|---|---|---|---|
| **N01** | SAST | `src/app/main.py` | Truy vấn cơ sở dữ liệu dùng cú pháp tham số hóa (`cursor.execute(sql, (param,))`) | D01 (SQLi) | Máy quét bỏ qua (PASS) |
| **N02** | SAST | `src/test/test_main.py` | Chuỗi giả lập (`mock_token = "dummy_12345"`) nằm trong thư mục test | D02 (Hardcoded Secret) | Máy quét bỏ qua (PASS) |
| **N03** | Secret | `src/app/main.py` | Đọc thông tin nhạy cảm qua biến môi trường (`os.environ.get("API_KEY")`) | D08 (Secret Token) | Máy quét bỏ qua (PASS) |
| **N04** | SCA | `src/requirements.txt` | Dùng requests 2.34.2 và urllib3 2.6.0; FastAPI baseline đã cao hơn bản sửa D11 | D09–D11 (SCA CVEs) | Máy quét bỏ qua các CVE đích (PASS) |
| **N05** | Image | `Code/DevSecOps/Dockerfile` | Chỉ thị `USER 10001` chạy dưới tài khoản không đặc quyền | D13 (Root user) | Máy quét bỏ qua (PASS) |
| **N06** | IaC | `infra/security_groups.tf` | Ingress cổng 22 chỉ cho phép truy cập từ dải mạng nội bộ VPC (`10.0.0.0/16`) | D16 (Open SSH 0.0.0.0/0) | Máy quét bỏ qua (PASS) |
| **N07** | K8s | `deploy/deployment.yaml` | Cấu hình tường minh cả `resources.requests` và `resources.limits` cho container | D22 (No resource limits) | Máy quét bỏ qua (PASS) |
| **N08** | CI | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Thêm action ghim SHA 40 ký tự | D28 (Mutable action ref) | Máy quét bỏ qua (PASS) |

---

## 4. Bảng 10 thay đổi sạch (Clean Changes C01–C10)

| ID | Lớp thay đổi | Tệp thay đổi | Nội dung thay đổi sạch | Kết quả kỳ vọng |
|---|---|---|---|---|
| **C01** | Ứng dụng | `src/app/main.py` | Bổ sung trường tùy chọn không bắt buộc vào Pydantic Model | PASS ở cả 3 Gate |
| **C02** | Ứng dụng | `src/app/main.py` | Bổ sung tài liệu hàm (docstring / comment giải thích) | PASS ở cả 3 Gate |
| **C03** | Kiểm thử | `src/test/test_main.py` | Viết thêm unit test kiểm tra logic hàm xử lý | PASS ở cả 3 Gate |
| **C04** | Phụ thuộc | `src/requirements.txt` | Cập nhật phiên bản thư viện sạch không chứa CVE | PASS ở cả 3 Gate |
| **C05** | IaC | `infra/security_groups.tf` | Bổ sung ghi chú (comment) mô tả mục đích Security Group | PASS ở cả 3 Gate |
| **C06** | IaC | `infra/iam.tf` | Bổ sung thẻ tag quản lý chi phí cho IAM Role | PASS ở cả 3 Gate |
| **C07** | IaC | `infra/s3.tf` | Bật tính năng mã hóa mặc định AES-256 cho bucket S3 | PASS ở cả 3 Gate |
| **C08** | K8s | `deploy/deployment.yaml` | Bổ sung annotation phục vụ Prometheus scraping metrics | PASS ở cả 3 Gate |
| **C09** | Image | `Code/DevSecOps/Dockerfile` | Thêm nhãn bảo mật `LABEL maintainer="Long"` | PASS ở cả 3 Gate |
| **C10** | CI | `lab/workflows-vuln/.github/workflows/ci-vuln.yml` | Bổ sung bước in thông báo hoàn tất vào summary | PASS ở cả 3 Gate |
