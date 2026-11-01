# E3 – Đánh giá thời gian pipeline (Pipeline Duration)

> **RQ4 / Mục 5.5**: Đánh giá thời gian thực thi pipeline bằng Trung vị (p50), Phân vị 90 (p90) và số lần đo (N).

## 1. Bảng số liệu thống kê thời gian thực thi (giây)

| Nhóm | Số lần đo (N) | Trung vị (p50) | Phân vị 90 (p90) | Phân vị 95 (p95) | Trung bình | Min | Max | Tê liệt (>10p) |
|---|---|---|---|---|---|---|---|---|
| **Clean** | 10 | 130.5s | 134.1s | 134.55s | 130.5s | 126.0s | 135.0s | Chưa xác thực |
| **Defect** | 28 | 152.5s | 163.3s | 164.65s | 152.93s | 142.0s | 166.0s | Chưa xác thực |
| **Tổng thể** | 38 | 147.5s | 162.3s | 164.15s | 147.03s | 126.0s | 166.0s | Chưa xác thực |

## 2. Nhận xét và kết luận

> **Chất lượng dữ liệu:** Bảng N=38 bên trên vẫn là dữ liệu thăm dò vì `runs.csv` không có run URL. Ngoài ra đã có một observation CI truy vết được; không gộp observation đó vào N=38.

- **Số dòng trong tệp (N):** 38 (28 mẫu lỗi và 10 mẫu sạch).
- **Trung vị (p50):** 147.5 giây (~2.46 phút), phản ánh chính xác thời gian thông thường của một PR mà không bị bóp méo bởi các ngoại lai.
- **Phân vị 90 (p90):** 162.3 giây (~2.71 phút) trong tập dữ liệu hiện có; không ngoại suy thành 90% PR nếu dữ liệu chưa truy vết.
- **Kiểm tra ngưỡng tê liệt trên dữ liệu hiện có:** Max ghi trong tệp là 166.0s so với ngưỡng 600 giây. Không dùng kết quả này để khẳng định độ ổn định nếu dữ liệu chưa truy vết được về GitHub Actions.

## 3. Một lần đo CI truy vết được

Nguồn: [GitHub Actions run #11, attempt 1](https://github.com/gialong611/DevSecOps_Project/actions/runs/41283884525/attempts/1), commit `00e4f40f7488c6407e99c0076f03c0c0ba344d3c`, fixture `baseline`.

| Job chạy song song | Thời gian |
|---|---:|
| `security-scan` | 23 giây |
| `iac` | 32 giây |
| `image` | 148 giây |

- Đường găng ước tính của ba job scan song song: **148 giây** (job dài nhất).
- Tổng công việc tuần tự ước tính: **203 giây**; đây không phải một lần chạy tuần tự đã đo.
- Trung vị ba job trong run đơn này là 32 giây; không đại diện cho phân phối thời gian pipeline.
- Chưa có lặp để so sánh cache bật/tắt hoặc chạy tuần tự/song song; chưa kết luận thời gian toàn workflow.
