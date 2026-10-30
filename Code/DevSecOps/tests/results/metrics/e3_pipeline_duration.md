# E3 – Đánh giá thời gian pipeline (Pipeline Duration)

> **RQ4 / Mục 5.5**: Đánh giá thời gian thực thi pipeline bằng Trung vị (p50), Phân vị 90 (p90) và số lần đo (N).

## 1. Bảng số liệu thống kê thời gian thực thi (giây)

| Nhóm | Số lần đo (N) | Trung vị (p50) | Phân vị 90 (p90) | Phân vị 95 (p95) | Trung bình | Min | Max | Tê liệt (>10p) |
|---|---|---|---|---|---|---|---|---|
| **Clean** | 10 | 130.5s | 134.1s | 134.55s | 130.5s | 126.0s | 135.0s | An toàn (PASS) |
| **Defect** | 28 | 152.5s | 163.3s | 164.65s | 152.93s | 142.0s | 166.0s | An toàn (PASS) |
| **Tổng thể** | 38 | 147.5s | 162.3s | 164.15s | 147.03s | 126.0s | 166.0s | An toàn (PASS) |

## 2. Nhận xét và kết luận

- **Số lần đo (N):** Tổng cộng 38 lần đo độc lập (28 lần với nhánh lỗi và 10 lần với nhánh sạch).
- **Trung vị (p50):** 147.5 giây (~2.46 phút), phản ánh chính xác thời gian thông thường của một PR mà không bị bóp méo bởi các ngoại lai.
- **Phân vị 90 (p90):** 162.3 giây (~2.71 phút), cho thấy 90% các PR hoàn thành kiểm tra trong khoảng thời gian này.
- **Kiểm tra ngưỡng tê liệt:** Thời gian tối đa ghi nhận là 166.0s, hoàn toàn thấp hơn nhiều so với ngưỡng 600 giây (10 phút). Pipeline đảm bảo tính ổn định và tính sẵn sàng cao.
