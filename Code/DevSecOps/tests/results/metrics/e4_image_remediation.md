# E4 – Ảnh hưởng của khắc phục lên image và SBOM

> **RQ5 / phân công Tài**: so sánh image trước và sau khi sửa;
> đo độ nhạy quyết định khi tín hiệu KEV/EPSS thay đổi. T0 là mô phỏng,
> không phải snapshot lịch sử có nguồn dẫn.

## 1. Khắc phục cấu trúc Dockerfile

| Chiều kiểm soát | Trước (Dockerfile.vuln) | Sau (Dockerfile) |
|---|---|---|
| USER không root | VI PHẠM | ĐẠT |
| Không ADD từ URL | VI PHẠM | ĐẠT |
| Không sshd / cổng 22 | VI PHẠM | ĐẠT |
| Multi-stage (không base đầy đủ) | VI PHẠM | ĐẠT |

Số chiều được khắc phục: **4/4**

## 2. Độ nhạy chính sách với tín hiệu KEV/EPSS

Mô phỏng chính sách với tín hiệu KEV/EPSS T0 được tạo có chủ đích; không phải snapshot lịch sử CISA/FIRST và không mô tả trạng thái thật của CVE.

| CVE | Quyết định G2 tại T0 | Quyết định G2 tại T1 |
|---|---|---|
| CVE-2024-35195 | BLOCK | WARN |
| CVE-2023-45803 | BLOCK | WARN |
| CVE-2024-24762 | BLOCK | BLOCK |

Số quyết định thay đổi giữa tín hiệu T0 mô phỏng và tập T1 đã ghim: **2**
- CVE-2024-35195: BLOCK → WARN
- CVE-2023-45803: BLOCK → WARN

## 3. So sánh image/SBOM (chế độ live)

Chưa có số liệu live. Chạy `python tests/e4_image_remediation.py --live --out-dir reports/e4` trên runner có Docker, Trivy và Syft để tạo báo cáo trước/sau cùng hai SBOM.

