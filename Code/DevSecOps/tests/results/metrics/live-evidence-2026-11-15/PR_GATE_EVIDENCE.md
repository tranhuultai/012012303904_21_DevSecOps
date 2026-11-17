# Bằng chứng gate trên pull request

Cập nhật: 2026-11-15. Thí nghiệm dùng fixture D01 SQL injection trong PR #1.
Fixture chỉ được gieo trên nhánh PR; commit cuối đã hoàn nguyên mã lỗi và không
đưa SQL injection vào `main`.

| Bước | Commit | GitHub Actions | Kết quả |
|---|---|---|---|
| PR sạch sau khi xử lý xung đột và cập nhật báo cáo | `3cc80d18c2028ea5bd50d724b660d9ef08fd4bcc` | [run 43729623939](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729623939) | test, scan, IaC, image và gate pass |
| Gieo lỗi D01 có chủ đích | `3e34d476a502b327c6a6deefaf400312aac21c16` | [run 43729980295](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729980295) | test, scan, IaC, image pass; gate G2 fail |
| Hoàn nguyên D01 | `71de64d169578265f79dba658e7c4778a25db183` | [run 43730231762](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730231762) | test, scan, IaC, image và gate pass |

## Chi tiết lượt bị chặn

Run `43729980295` ghi hai blocker HIGH trong `gate_input.json`:

- `rules.semgrep.python.sqli.concatenation`
- `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

Step `Chạy Security Gate (Conftest + Rego)` thất bại với exit code 1; các job
Python tests, security scans, IaC và image đều thành công. Đây là bằng chứng lỗi
gieo cài đã tới scanner, được policy G2 chặn và được khắc phục ở commit kế tiếp.

## Trạng thái required checks

GitHub hiện chưa buộc check nào trước khi merge PR: `gh pr checks --required`
trả về “no required checks reported”, endpoint branch protection trả HTTP 404,
và danh sách ruleset không có kết quả. Tài khoản thực hiện cập nhật có quyền
push nhưng quyền quản trị repository là `admin=false`, nên không thể bật rule.

Các check context đã xác nhận trên run thành công là:

- `Run Python tests`
- `gate (Conftest Rego)`

Repo admin cần vào **Settings → Rules → Rulesets**, tạo ruleset áp dụng cho nhánh
`main`, bật yêu cầu pull request và required status checks, rồi chọn đúng hai
context trên. Sau đó cần xác minh lại bằng PR. Đến khi việc đó hoàn tất, không
diễn giải các run ở trên thành bằng chứng branch protection đã chặn merge.
