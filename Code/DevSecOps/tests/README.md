## Mục 1. Câu hỏi nghiên cứu (RQ1–RQ5)
RQ1 (E1): Mức độ hiệu quả và tỷ lệ chặn nhầm của chính sách an ninh mặc định là bao nhiêu?
RQ2 (E1): Chính sách mặc định tạo ra bao nhiêu cảnh báo và kéo dài thời gian chạy pipeline ra sao?
RQ3 (E2): Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?
RQ4 (E3): Việc thay đổi cấu hình kiểm tra ảnh hưởng thế nào đến thời gian chạy và số cảnh báo trên mỗi PR?
RQ5 (E4): Kết quả phân tích thay đổi như thế nào khi cập nhật cơ sở dữ liệu lỗ hổng theo thời gian?

## Mục 2. Định nghĩa "Tê liệt" pipeline bằng con số
Pipeline được coi là bị tê liệt khi dính 1 trong các dấu hiệu sau:
1 thay đổi sạch bị chặn (False block).
Pipeline chạy quá 10 phút.
1 PR nhận hơn 20 cảnh báo.

## Mục 3. Trạng thái nguồn dữ liệu đang commit

- `findings.csv` là bộ finding dự kiến gắn với lỗi gieo cài, không phải bản xuất
  thô của Semgrep/Gitleaks/Trivy/Checkov.
- `decisions.csv` ghi các quyết định fixture theo policy. E1/E2 dùng các quyết
  định này; chúng không chứng minh scanner đã bắt lỗi nếu thiếu báo cáo thô và
  liên kết GitHub Actions cho từng mẫu.
- `runs.csv` hiện không có URL workflow run, mỗi `change_id` chỉ có một dòng,
  và không phân nhóm cache bật/tắt hoặc chế độ song song. Không dùng các thống
  kê này để kết luận thời gian CI đại diện cho pipeline.
- Negative controls N01–N08 hiện mới có mô tả trong ground truth; chưa có lần
  chạy scanner độc lập ghi nhận kết quả cho từng control.
- E4 chỉ được coi là so sánh image/SBOM hoàn tất khi output live chứa cả hai
  báo cáo Trivy và hai SBOM Syft. Workflow image chạy script này và lưu output
  trong artifact `report-image`.

Khi thu thập lại, lưu artifact scanner không chuẩn hóa, kết quả gate của G0/G1/G2,
URL run, hash commit, phiên bản tool, thời gian bắt đầu/kết thúc và cấu hình
cache/song song. Không thay dữ liệu fixture bằng số đo CI nếu chưa lưu nguồn.
