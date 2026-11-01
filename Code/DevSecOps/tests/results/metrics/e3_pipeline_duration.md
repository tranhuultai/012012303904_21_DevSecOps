# E3 – Đánh giá thời gian pipeline (Pipeline Duration)

> **RQ4 / Mục 5.5**: Đánh giá thời gian thực thi pipeline bằng Trung vị (p50), Phân vị 90 (p90) và số lần đo (N).

## 1. Bảng số liệu thống kê thời gian thực thi (giây)

| Nhóm | Số lần đo (N) | Trung vị (p50) | Phân vị 90 (p90) | Phân vị 95 (p95) | Trung bình | Min | Max | Tê liệt (>10p) |
|---|---|---|---|---|---|---|---|---|
| **Clean** | 10 | 130.5s | 134.1s | 134.55s | 130.5s | 126.0s | 135.0s | Chưa xác thực |
| **Defect** | 28 | 152.5s | 163.3s | 164.65s | 152.93s | 142.0s | 166.0s | Chưa xác thực |
| **Tổng thể** | 38 | 147.5s | 162.3s | 164.15s | 147.03s | 126.0s | 166.0s | Chưa xác thực |

## 2. Nhận xét và kết luận

> **Chất lượng dữ liệu:** Chưa truy vết được: runs.csv không có liên kết GitHub Actions cho từng phép đo; các giá trị chỉ nên xem là dữ liệu thăm dò.

- **Số dòng trong tệp (N):** 38 (28 mẫu lỗi và 10 mẫu sạch).
- **Trung vị (p50):** 147.5 giây (~2.46 phút), phản ánh chính xác thời gian thông thường của một PR mà không bị bóp méo bởi các ngoại lai.
- **Phân vị 90 (p90):** 162.3 giây (~2.71 phút) trong tập dữ liệu hiện có; không ngoại suy thành 90% PR nếu dữ liệu chưa truy vết.
- **Kiểm tra ngưỡng tê liệt trên dữ liệu hiện có:** Max ghi trong tệp là 166.0s so với ngưỡng 600 giây. Không dùng kết quả này để khẳng định độ ổn định nếu dữ liệu chưa truy vết được về GitHub Actions.
