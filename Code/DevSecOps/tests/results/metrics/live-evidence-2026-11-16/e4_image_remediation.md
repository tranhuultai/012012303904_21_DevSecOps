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

| Chỉ số | Trước | Sau | Delta |
|---|---:|---:|---:|
| Gói trong SBOM | 22943 | 2856 | -20087 |
| Lỗ hổng CRITICAL | 18 | 0 | -18 |
| Lỗ hổng HIGH | 804 | 47 | -757 |
| Lỗ hổng MEDIUM | 1746 | 89 | -1657 |
| Lỗ hổng LOW | 1819 | 65 | -1754 |
| Lỗ hổng UNKNOWN | 99 | 5 | -94 |
| Tổng lỗ hổng | 4486 | 206 | -4280 |

### Nhận dạng image và tính so sánh

- before: image ID `sha256:f1cfb59eb412a73669278891d1072bcc4d7fe92a8096bc98525bb951e6a7f83e`, Python `3.13.18`, OS `{'Family': 'debian', 'Name': '13.7'}`, architecture `amd64`.
- after: image ID `sha256:ed6c553e3778250b60d99db0b8f5313effe279d7b68f0a9419b339eab71cd02e`, Python `3.13.18`, OS `{'Family': 'debian', 'Name': '13.7'}`, architecture `amd64`.
- Trạng thái E4 live: **comparable**; được phép quy kết delta cho thay đổi Dockerfile: **True**.
- Cùng phiên bản Python: **True**; cùng OS: **True**; cùng architecture: **True**; cùng Trivy DB snapshot đã xác minh theo từng lần quét: **True**; snapshot mức job đã ghi: **True**.
- CI run: `43743317883`.
- `before` config digest: `sha256:f1cfb59eb412a73669278891d1072bcc4d7fe92a8096bc98525bb951e6a7f83e`; manifest digest trên registry: `chưa có`; Dockerfile SHA-256: `23916a54ea387c265f15656dc5f096440a4ec46a660115a64535077ec9c47e7a`.
- `after` config digest: `sha256:ed6c553e3778250b60d99db0b8f5313effe279d7b68f0a9419b339eab71cd02e`; manifest digest trên registry: `chưa có`; Dockerfile SHA-256: `fbea0553770e056681e46be7978b77440a1a44addc26733b786de9c89ef97d04`.
- Trivy vulnerability DB cập nhật: `2026-11-15 12:50:30.599818283 +0000 UTC`.

