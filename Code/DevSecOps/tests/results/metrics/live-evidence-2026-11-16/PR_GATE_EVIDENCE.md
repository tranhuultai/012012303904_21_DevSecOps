# Bằng chứng gate và required checks trên pull request

Cập nhật: 2026-11-16. PR #1 đã được dùng để kiểm tra cả lượt lỗi bị gate chặn,
lượt sửa được cho qua và trạng thái check bắt buộc trên nhánh `main`.

| Bước | Commit/run | Kết quả |
|---|---|---|
| PR sạch sau khi xử lý xung đột | [run 43729623939](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729623939) | Python tests, scan, IaC, image và gate pass |
| Gieo lỗi D01 SQL injection | [run 43729980295](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729980295) | Scanner jobs pass; gate G2 fail với blocker HIGH |
| Hoàn nguyên lỗi D01 | [run 43730231762](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730231762) | Python tests, scan, IaC, image và gate pass |
| Lượt CI cuối trên nhánh PR | [run 43730524460](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730524460) | Cả 6 check context pass trước khi PR được merge |

## Kết quả block/pass

Run `43729980295` ghi hai blocker HIGH trong `gate_input.json`:

- `rules.semgrep.python.sqli.concatenation`
- `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

Step `Chạy Security Gate (Conftest + Rego)` kết thúc với exit code 1; các job
Python tests, security scans, IaC và image đều thành công. Sau khi hoàn nguyên
fixture D01, run `43730231762` cho gate pass. Đây là bằng chứng gate chặn lỗi
gieo cài và cho qua sau khắc phục.

## Ruleset đang áp dụng cho `main`

Đã đọc trực tiếp cấu hình GitHub repository ruleset ngày 2026-11-16:

- Ruleset **Protect main** đang `active`, target `refs/heads/main`.
- Bắt buộc tạo pull request trước khi cập nhật nhánh; yêu cầu 0 lượt review.
- Bắt buộc 6 status checks pass trước khi cập nhật nhánh:
  `Prepare Trivy and Grype vulnerability DB snapshots`, `Run Python tests`,
  `Security scans (collection mode)`, `iac`, `image`, `gate (Conftest Rego)`.
- Bật chặn xóa nhánh và force push; bypass được đặt là `never`.
- Tùy chọn yêu cầu nhánh phải cập nhật trước khi merge đang tắt (`strict=false`).
- Lệnh `gh pr checks 1 --required` hiện trả về đủ 6 check bắt buộc và cả 6 đều
  pass. Tuy nhiên, PR #1 được merge lúc `2026-11-15T15:35:38Z`, còn ruleset được
  tạo lúc `2026-11-15T23:08:08+07:00` (16:08:08Z). Vì vậy PR #1 merge trước khi
  ruleset tồn tại; run `43730524460` xác nhận các check đã pass nhưng không chứng
  minh ruleset đã chặn merge ở PR đó.

Ruleset active và danh sách check bắt buộc đã được xác minh qua API. Cần một PR
mới được tạo sau thời điểm bật ruleset để chứng minh trực tiếp GitHub từ chối
merge khi check pending/fail rồi cho merge khi cả sáu check pass. Quy tắc hiện
không bắt buộc review hoặc cập nhật nhánh trước khi merge; cần trình bày đúng
các giới hạn này.
