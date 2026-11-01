## Mục 1. Câu hỏi nghiên cứu (RQ1–RQ5)
RQ1 (E1): Mức độ hiệu quả và tỷ lệ chặn nhầm của chính sách an ninh mặc định là bao nhiêu?
RQ2 (E1): Chính sách mặc định tạo ra bao nhiêu cảnh báo và kéo dài thời gian chạy pipeline ra sao?
RQ3 (E2): Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?
RQ4 (E3): Việc thay đổi cấu hình kiểm tra ảnh hưởng thế nào đến thời gian chạy và số cảnh báo trên mỗi PR?
RQ5 (E4): Quyết định gate thay đổi thế nào khi tín hiệu KEV/EPSS khác nhau, và việc vá image đổi SBOM/lỗ hổng ra sao?

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
- Patch N01–N08 hiện có thể chạy độc lập qua workflow dispatch. Chưa có lần
  chạy CI thật ghi nhận scanner false positive và gate false block cho từng control.
- E4 độ nhạy KEV/EPSS T0 hiện là mô phỏng; chỉ kết luận thay đổi dữ liệu theo
  thời gian khi lưu được ít nhất hai snapshot có ngày/nguồn. E4 chỉ được coi là
  so sánh image/SBOM hoàn tất khi output live chứa cả hai
  báo cáo Trivy và hai SBOM Syft. Workflow image chạy script này và lưu output
  trong artifact `report-image`.
- `report-gate` có thêm `reports/experiment/observation.json`: bản ghi baseline
  của một workflow run, gồm run URL, commit, phiên bản tool đã ghim, quyết định
  gate, metadata thời điểm cập nhật vulnerability DB của Trivy, thống kê finding
  và SHA-256 của các báo cáo thô. `evidence_status` là
  `partial` nếu thiếu báo cáo/timing/gate hoặc không có run URL. Bản ghi này
  giúp truy vết một lần chạy, nhưng chưa thay cho phép thử từng patch D/N/C hay
  các lần lặp E3. Cấu trúc được mô tả tại
  `schemas/scan-observation.schema.json` và workflow xác thực schema sau khi tạo.
- Chạy thủ công workflow `DevSecOps CI` với `fixture_id=baseline`, sau đó chạy
  từng `D01`–`D28`, `C01`–`C10` và `N01`–`N08` để áp patch độc lập, quét working tree và lưu
  gate của cả G0/G1/G2. Tải artifact `report-gate` của các run vào cùng thư mục,
  rồi dùng `python tests/analyze_fixture_observations.py --input-dir <thu_muc_artifact>
  --out-dir results/metrics/live`. Bộ tổng hợp so fingerprint với baseline cùng
  commit/tool versions/Trivy DB snapshot và chỉ tính finding mới trên file mục tiêu. Báo cáo tách
  scanner false positive trên N controls khỏi gate false block trên C changes.
  Trạng thái chỉ là complete sau khi đủ tất cả D/C/N và một baseline cùng commit.

Khi thu thập lại, lưu artifact scanner không chuẩn hóa, kết quả gate của G0/G1/G2,
URL run, hash commit, phiên bản tool, thời gian bắt đầu/kết thúc và cấu hình
cache/song song. Không thay dữ liệu fixture bằng số đo CI nếu chưa lưu nguồn.

## Ước tính chi phí runner

Sau khi tải artifact có `e3-ci-run-timing.json`, ước tính runner-minutes bằng
đơn giá và số lượt chạy/tháng do người báo cáo nhập (kèm ngày/nguồn giá):

```bash
python tests/estimate_ci_cost.py \
  --timing reports/e3-ci-run-timing.json \
  --rate-usd-per-runner-minute 0.01 \
  --rate-source "điền URL bảng giá và ngày tra cứu" \
  --runs-per-month 100 \
  --out reports/e3-cost-estimate.json
```

Đây là ước tính lập kế hoạch, không phải hóa đơn; script nêu rõ các khoản chưa
tính như làm tròn phút, quota miễn phí, lưu trữ và truyền dữ liệu. Thay ví dụ đơn
giá bằng số liệu có nguồn tại thời điểm lập báo cáo.
