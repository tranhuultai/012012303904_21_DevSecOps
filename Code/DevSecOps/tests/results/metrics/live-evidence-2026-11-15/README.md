# Bằng chứng thí nghiệm live – 2026-11-15 (đã được thay thế)

Đây là gói tổng hợp lịch sử, không còn là bộ số liệu hiện hành. Dùng bộ mới tại
[`live-evidence-2026-11-16`](../live-evidence-2026-11-16/README.md) khi trích dẫn
kết quả E1–E4 hoặc trạng thái required checks.

Thư mục này giữ bản tổng hợp nhỏ, có thể xem trực tiếp trên GitHub. Các báo cáo
được tính từ observation và raw scanner report của GitHub Actions; không dùng
`decisions.csv`, `findings.csv` hoặc `runs.csv` làm dữ liệu phát hiện.

| Tệp | Nội dung |
|---|---|
| `e1_e2_live_observations.md` / `.json` | Kết quả scanner và policy G0/G1/G2 trên 38 fixture D/C và 8 negative control N. JSON lưu từng fixture, run URL, commit và finding/policy summary. |
| `e1_e2_source_manifest.json` | 48 observation gồm 2 baseline, 38 D/C và 8 N; lưu run URL, SHA-256 observation, commit và Grype DB snapshot. Đường dẫn máy cá nhân đã được loại bỏ. |
| `e3_live_cache_comparison.md` / `.json` | 5 lượt cold và 5 lượt warm trên cùng commit; có run ID, tool/database snapshot, wall time, runner-minutes và thời gian từng job. |
| `e4_image_remediation.md` / `.json` | So sánh image/SBOM trước và sau remediation, metadata môi trường, config digest cục bộ, Dockerfile SHA-256 và trạng thái khả năng quy kết. |

## Run nguồn

- E1/E2: từng run URL và SHA-256 observation nằm trong `e1_e2_source_manifest.json`.
- E3: cold `43720462402`, `43720623390`, `43720826878`, `43721027209`, `43721228607`; warm `43721428720`, `43721628634`, `43721816029`, `43722022195`, `43722229167`.
- E4: [run 43723320787](https://github.com/gialong611/DevSecOps_Project/actions/runs/43723320787/attempts/1).

Raw report và observation theo lượt nằm trong artifact GitHub Actions của các run
nguồn; artifact có thời hạn lưu của GitHub. Các tệp ở đây là bản tổng hợp đã
commit, không thay thế raw report khi cần tái phân tích.

## Diễn giải

- E1/E2 chỉ mô tả tập fixture gieo cài đã đo; không suy rộng thành tỷ lệ phát hiện
  trong môi trường production.
- E3 cho thấy cache pip warm chậm hơn 6 giây trong mẫu đo; không kết luận cache
  luôn làm pipeline chậm hơn.
- E4 so sánh hai image local trên cùng Python, OS, kiến trúc và snapshot Trivy.
  Chưa có registry manifest digest; kết luận áp dụng cho toàn bộ thay đổi image/
  Dockerfile trong phép đo.
