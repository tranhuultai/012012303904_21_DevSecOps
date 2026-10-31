# E4 – Ảnh hưởng của khắc phục lên image và SBOM

> **RQ5 / phân công Tài**: so sánh image trước và sau khi sửa;
> đo tác động của việc cập nhật cơ sở dữ liệu lỗ hổng theo thời gian.

## 1. Khắc phục cấu trúc Dockerfile

| Chiều kiểm soát | Trước (Dockerfile.vuln) | Sau (Dockerfile) |
|---|---|---|
| USER không root | VI PHẠM | ĐẠT |
| Không ADD từ URL | VI PHẠM | ĐẠT |
| Không sshd / cổng 22 | VI PHẠM | ĐẠT |
| Multi-stage (không base đầy đủ) | VI PHẠM | ĐẠT |

Số chiều được khắc phục: **4/4**

## 2. Trôi dữ liệu lỗ hổng (KEV/EPSS T0 → T1)

| CVE | Quyết định G2 tại T0 | Quyết định G2 tại T1 |
|---|---|---|
| CVE-2022-42969 | BLOCK | BLOCK |
| CVE-2023-45803 | BLOCK | BLOCK |
| CVE-2024-24762 | WARN | BLOCK |

Số quyết định thay đổi khi cập nhật dữ liệu: **1**
- CVE-2024-24762: WARN → BLOCK

## 3. So sánh image/SBOM (chế độ live)

Máy này không có đủ docker/trivy/syft nên bỏ qua phần live; số liệu live được thu trên CI (job `image`).

