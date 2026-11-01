## Mục 1. Câu hỏi nghiên cứu (RQ1–RQ5)
RQ1 (E1): Mức độ hiệu quả và tỷ lệ chặn nhầm của chính sách an ninh mặc định là bao nhiêu?
RQ2 (E1): Chính sách mặc định tạo ra bao nhiêu cảnh báo và kéo dài thời gian chạy pipeline ra sao?
RQ3 (E2): Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?
RQ4 (E3): Việc thay đổi cấu hình kiểm tra ảnh hưởng thế nào đến thời gian chạy và số cảnh báo trên mỗi PR?
RQ5 (E4): Quyết định gate thay đổi thế nào khi tín hiệu KEV/EPSS khác nhau, và việc vá image đổi SBOM/lỗ hổng ra sao?

## Thiết kế đo và cách diễn giải

| Thí nghiệm | Đơn vị đo và biến | Chỉ số đầu ra | Cách kết luận |
|---|---|---|---|
| E1 | Một fixture D/C/N trên cùng commit baseline; tool versions và metadata Trivy DB phải khớp | Finding mới khớp tool/rule/file; phát hiện đúng hoặc bỏ sót theo D; finding mới trên C/N | Tính recall trên D; báo scanner false positive trên N riêng với finding trên C |
| E2 | Cùng một observation được đánh giá bằng G0, G1, G2 | TP/FN trên D; FP/TN trên C; số N bị chặn | So recall và false-block rate; báo N controls riêng, không gộp false positive scanner với false block gate |
| E3 | Baseline giống nhau; cấu hình cache và mức song song là biến độc lập; tối thiểu 5 lần cho mỗi cấu hình | Thời gian mỗi job và thời gian tường của workflow | Báo median và min–max (hoặc IQR); phân biệt tổng runner-minutes với đường găng của job song song |
| E4 | Cùng source/architecture và snapshot cơ sở dữ liệu; image trước/sau là biến | Image digest, package count, CVE theo severity, SBOM trước/sau | Chỉ quy thay đổi cho remediation khi tool version và Trivy DB snapshot giống nhau; nếu DB khác, báo riêng và không quy toàn bộ chênh lệch cho bản vá |

Baseline dùng fixture `baseline` trên commit gốc. Patch D/C/N được áp độc lập
trong runner; không chạy nhiều patch cùng một observation. Mỗi lượt phải lưu run
URL, commit, tool versions, metadata database, cấu hình cache/song song, artifact
thô và timing. Nếu Trivy DB đổi giữa các lượt thì thu lại nhóm với baseline mới
hoặc phân tích thành nhóm snapshot tách biệt. Báo cáo số liệu từ fixture chỉ có
ý nghĩa trong phạm vi các mẫu gieo cài này; không suy rộng thành tỷ lệ lỗ hổng
ngoài thực tế.

## Mục 2. Định nghĩa "Tê liệt" pipeline bằng con số
Pipeline được coi là bị tê liệt khi dính 1 trong các dấu hiệu sau:
1 thay đổi sạch bị chặn (False block).
Pipeline chạy quá 10 phút.
1 PR nhận hơn 20 cảnh báo.

## Mục 3. Trạng thái nguồn dữ liệu đang commit

- Baseline CI mới nhất đã phân tích là commit
  `cbcef8e32d5b007229be5e424409e8ee00fe278e`:
  [run #13](https://github.com/gialong611/DevSecOps_Project/actions/runs/41288998886).
  Metadata và ID artifact nằm ở `results/metrics/ci_baseline_latest.json`.
  Gate có 275 findings, 0 blockers, 30 warnings và quyết định `WARN`; đây là
  run `push`, còn ngưỡng 20 warnings áp dụng cho PR nên chưa đo trực tiếp PR bị
  tê liệt.
- Raw artifact E4 đã được đọc: Trivy giảm 4.721→188 record (-4.533), gồm
  CRITICAL 21→0, HIGH 531→52, MEDIUM 2.037→71, LOW 2.030→64, UNKNOWN 102→1;
  SBOM giảm 22.921→2.860 package (-20.061). Cả hai image dùng Trivy 0.76.1,
  cùng snapshot DB `2026-11-01 07:08:40 UTC`, Debian 13.7 và amd64; Python
  khác phiên bản 3.12.15→3.12.16. Vì vậy không quy delta cho từng kiểm soát
  riêng lẻ. Hai image chỉ có local image ID, không có `RepoDigests`.
- E3 run #13 có 28s (security-scan), 37s (IaC), 171s (image); critical path
  của ba job scan song song là 171s. Tổng 236s là phép cộng tuần tự ước tính,
  không phải workflow tuần tự đã đo. Run #11 có 148s trên commit khác, không
  gộp với #13 thành lần lặp. Chưa so sánh cache bật/tắt hoặc mức song song.
- Checkov artifact `checkov.json` là stream gồm 3 JSON document liên tiếp.
  Loader của dự án có thể đọc stream, còn `json.load` tiêu chuẩn báo `Extra
  data` ở dòng 6354. Workflow local hiện lưu nguyên bản vào
  `checkov.stream.json` rồi dùng `jq -s` tạo `checkov.json` dạng JSON array;
  cần CI run tiếp theo để xác nhận output mới.
- 15 cảnh báo MEDIUM đã được phân nhóm: 5 Python, 5 pip, 2 pytest và 3
  Starlette. Các cập nhật Python 3.13.18, pip 26.2.2 và pytest 9.0.3 trong
  working tree nhắm tới 12 cảnh báo; 3 cảnh báo Starlette được hoãn để đánh
  giá tương thích. 18 warning là dự báo nếu cả 12 advisory biến mất và không
  có cảnh báo mới, không phải kết quả đo. Xem
  `results/metrics/ci_warning_triage_run13.md`.
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
- `report-gate` có `reports/experiment/observation.json`: bản ghi cho đúng một
  workflow run, có thể là baseline hoặc một patch fixture. Bản ghi gồm run URL,
  commit, phiên bản tool đã ghim, quyết định gate, metadata thời điểm cập nhật
  vulnerability DB của Trivy, thống kê finding và SHA-256 của các báo cáo thô.
  `evidence_status` là
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
  Bộ tổng hợp yêu cầu các run có cùng phiên bản công cụ và cùng Trivy database
  snapshot. Nếu metadata DB khác baseline, không gộp các run đó; chạy lại cả
  nhóm với một baseline mới để tránh so findings từ hai tập dữ liệu lỗ hổng khác
  nhau.

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
