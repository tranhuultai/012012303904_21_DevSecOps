# Dữ liệu Known Exploited Vulnerabilities (KEV) & Exploit Prediction Scoring System (EPSS)

Thư mục này lưu trữ danh mục các lỗ hổng đã bị khai thác trong thực tế (Known Exploited Vulnerabilities - CISA KEV) và điểm dự đoán khai thác (EPSS - Exploit Prediction Scoring System), phục vụ cơ chế ra quyết định an ninh theo ngữ cảnh tại Security Gate G2.

## Người phụ trách: Hoàng Gia Long (Long - gialong611)

### 1. Phân biệt CVSS, KEV và EPSS
- **CVSS (Common Vulnerability Scoring System):** Thang điểm 0–10 đo mức độ nghiêm trọng kỹ thuật lý thuyết dựa trên đặc tính lỗ hổng (tính bảo mật, toàn vẹn, khả dụng). CVSS **không** cho biết lỗ hổng đã bị khai thác trong thực tế hay chưa.
- **KEV (CISA Known Exploited Vulnerabilities):** Danh mục các CVE đã có bằng chứng xác thực bị tin tặc khai thác ngoài đời thực. Đây là cơ sở ưu tiên khắc phục tối khẩn cấp.
- **EPSS (Exploit Prediction Scoring System):** Mô hình máy học dự đoán xác suất (từ 0.00 đến 1.00, tức 0% đến 100%) một lỗ hổng sẽ bị khai thác trong vòng 30 ngày tới.

### 2. Vai trò trong Gate G2
Trong chính sách G2 (`policy/g2/gate.rego`):
- **KEV (BLOCK):** Bất kỳ phát hiện nào có `kev: true` sẽ bị chặn ngay lập tức ở mọi mức nghiêm trọng kỹ thuật.
- **EPSS cao (BLOCK):** Lỗ hổng có `epss >= 0.10` (xác suất khai thác từ 10% trở lên) sẽ bị chặn trực tiếp.
- **EPSS trung bình (WARN):** Lỗ hổng có `0.01 <= epss < 0.10` được đưa vào danh sách cảnh báo để nhóm phát triển theo dõi mà không làm nghẽn pipeline.

### 3. Cấu trúc tệp dữ liệu:
- `cisa_kev_subset.json`: Tập con các CVE phục vụ thực nghiệm E1/E2 trong đề tài.

