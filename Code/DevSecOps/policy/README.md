# Chính sách gate (policy/)

Thư mục này có ba chính sách đối chứng viết bằng Rego v1:

- `g0/`: chỉ báo cáo, không chặn gì (mốc so sánh).
- `g1/`: chặn mọi phát hiện từ mức Medium trở lên, không xét KEV, bản vá hay ngoại lệ.
- `g2/`: chặn theo tầng, có xét KEV, bản vá, độ tin cậy và ngoại lệ có hạn.

## Quy tắc: mỗi lần chỉ dùng một thư mục

Cả ba thư mục đều khai báo `package main`. Nếu nạp chung (ví dụ `opa test policy`
hoặc truyền nhiều thư mục qua `-p`), các luật `deny` của chúng bị gộp thành một
bộ luật, nên kết quả test và quyết định của gate sẽ sai.
Gate trong CI cũng chỉ truyền một thư mục chính sách mỗi lần.

## Chạy test

Chạy lần lượt từng thư mục:

    .\tests\run_policy_tests.ps1

Script thoát với mã 0 khi cả ba nhóm xanh, mã 1 khi có nhóm đỏ.