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

## Mục 3. Kết quả thực nghiệm live

Các kết quả dưới đây được tính từ raw scanner reports và observation của GitHub
Actions, không dùng `findings.csv`, `decisions.csv` hay `runs.csv` làm thay dữ liệu
phát hiện.

| Đo lường | Kết quả live mới nhất |
|---|---|
| E1 – D/C/N | 38/38 fixture D/C và 8/8 N hoàn tất; scanner phát hiện 28/28 lỗi D; 0/10 C có finding mới; 0/8 N có finding mới theo rule đích. |
| E2 – G1 | TP/FN/FP/TN = 28/0/0/10; block recall 28/28 trường hợp kỳ vọng BLOCK; blocker khớp rule đích 27/28; false-block C 0/10, N 1/8. |
| E2 – G2 | TP/FN/FP/TN = 23/0/0/15; block recall 23/23 trường hợp kỳ vọng BLOCK; blocker khớp rule đích 22/23; false-block C 0/10, N 0/8. Năm lỗi D còn lại được policy xếp WARN. |
| E2 – G0 | Không có trường hợp kỳ vọng BLOCK nên recall không áp dụng; 0/8 negative control bị chặn. |
| E3 – cold/warm | Mỗi profile N=5, cùng commit và snapshot Trivy/Grype. Wall median 111s/125s, IQR 3s/10s, p90 115,8s/126,6s; scan stage 87s/97s; tổng runner-minutes median 3,45/3,63. |
| E4 – image/SBOM | 4.486 → 206 bản ghi Trivy; 18 → 0 CRITICAL; SBOM 22.943 → 2.856 thành phần. Cùng Python 3.13.18, Debian 13.7, amd64, Trivy 0.76.1 và DB snapshot. |

E1/E2 có 47 observation nguồn: một baseline và 46 fixture D/C/N, cùng commit
`135606475be9d66842121135631d853a63c1e480`. Kết quả được tính từ raw report và
finding mới so với baseline; không lấy `decisions.csv` làm dữ liệu phát hiện.
G1 chặn mọi lỗi được kỳ vọng BLOCK; G2 chặn 23 trường hợp kỳ vọng BLOCK và cảnh
báo 5 lỗi ở mức WARN. G1 chặn 1/8 negative control trong khi G2 chặn 0/8.

E3 warm chậm hơn median 14 giây (12,61%) trong mẫu đo. Chỉ pip cache thay đổi;
scanner jobs vẫn chạy song song. E4 có config digest và Dockerfile SHA-256 cục
bộ nhưng chưa có manifest digest registry; kết luận áp dụng cho toàn bộ thay đổi
Dockerfile/image, không tách riêng từng package. Số CRITICAL `18 → 0` lấy từ cặp
raw report before/after của cùng run E4.

Chi tiết hiện hành nằm tại
`tests/results/metrics/live-evidence-2026-11-16/`. Manifest E1/E2 lưu run URL,
commit, SHA-256 observation/raw report, tool versions và DB snapshot; JSON E3 lưu
10 run ID cùng thống kê và thời gian từng job; JSON E4 lưu raw report hashes và
metadata so sánh. Các raw report đầy đủ nằm trong artifact của từng run GitHub
Actions và tuân theo thời hạn lưu artifact. Xem
[E1/E2](results/metrics/live-evidence-2026-11-16/e1_e2_live_observations.md),
[E3](results/metrics/live-evidence-2026-11-16/e3_live_cache_comparison.md),
[E4](results/metrics/live-evidence-2026-11-16/e4_image_remediation.md) và
[bằng chứng PR/ruleset](results/metrics/live-evidence-2026-11-16/PR_GATE_EVIDENCE.md).

Các tệp `e1_g0_metrics.json`, `e1_g1_metrics.json`, `e1_g2_metrics.json` và
`e2_policy_comparison.json` ở thư mục `results/metrics/` là policy replay thăm
dò từ `decisions.csv`; chúng được giữ để đối chiếu lịch sử, không thay cho kết
quả live trong gói ngày 2026-11-16.

### Giới hạn cần giữ rõ trong báo cáo

- E3 sử dụng 5 cold và 5 warm run thành công; một lượt warm-up được loại khỏi thống kê.
  Một số baseline có `WARN`, nhưng không có baseline nào bị G2 `BLOCK` trong nhóm đo.
- PR #1 có lượt thử block/pass có kiểm soát: D01 SQL injection bị gate G2 chặn
  tại [run 43729980295](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729980295);
  sau khi hoàn nguyên fixture, [run 43730231762](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730231762)
  pass. Xem `tests/results/metrics/live-evidence-2026-11-16/PR_GATE_EVIDENCE.md`.
- Ruleset `Protect main` đang active, yêu cầu PR và sáu check: DB snapshots,
  Python tests, security scans, IaC, image và gate. PR #1 merge trước thời điểm
  bật ruleset; cần PR tiếp theo để chứng minh ruleset chặn merge thật. Cấu hình
  chi tiết có trong `PR_GATE_EVIDENCE.md`.
- T0 KEV/EPSS trong E4 là mô phỏng, không phải snapshot lịch sử CISA/FIRST.
- Observation schema v6 tại `schemas/scan-observation.schema.json` lưu run URL,
  commit, tool versions, timing, cache profile, report SHA-256, quyết định G0/G1/G2
  và provenance snapshot Trivy/Grype.

### Thu thập lại fixture D/C/N và E3

Để thu thập study mới, chạy từ thư mục `Code/DevSecOps` trên máy đã đăng nhập
`gh auth login` và có quyền dispatch workflow, đọc run và tải artifact. Script
tự ghim một SHA cho toàn bộ study, tải artifact nhỏ cho từng run, ghi URL/run
ID/job timing, và hỗ trợ tiếp tục bằng `--resume`.

```bash
# Baseline + 28 D + 10 C + 8 N, sau đó tạo báo cáo live E1/E2.
python tests/run_fixture_matrix.py --ref main --out-dir tests/results/live-study --parallelism 4

# Ít nhất 5 lượt mỗi profile; chạy warm-up trước và loại khỏi thống kê.
python tests/run_fixture_matrix.py --ref main --skip-fixtures \
  --e3-cold-repeats 5 --e3-warm-repeats 5 \
  --out-dir tests/results/e3-live

# Tiếp tục sau khi bị ngắt, dùng đúng thư mục và cùng commit.
python tests/run_fixture_matrix.py --ref main --skip-fixtures \
  --e3-cold-repeats 5 --e3-warm-repeats 5 \
  --out-dir tests/results/e3-live --resume
```

Fixture matrix mặc định gồm 47 lượt (baseline + 46 mẫu); baseline chạy trước,
sau đó D/C/N chạy song song tối đa 4 workflow. E3 thêm 11 lượt (1 warm-up + 5
cold + 5 warm). Workflow dùng cache DB Trivy/Grype có snapshot ID cố định; nếu
snapshot hoặc tool version khác baseline, analyzer E1/E2/E3 đánh dấu chưa đủ và
không gộp số liệu. E3 chỉ giữ run thành công, hoặc run baseline mà test, DB và
cả ba job scanner thành công và gate G2 là job duy nhất bị chặn; các lỗi khác
vẫn bị loại. E3 đo pip cache trong khi scanner jobs vẫn chạy song song; không
diễn giải như so sánh tuần tự.

Sau study, kiểm tra JSON/Markdown tổng hợp, URL từng case trong `run-index.json`
và hash artifact trước khi cập nhật báo cáo. Bộ dữ liệu Markdown/JSON hiện hành
đã được lưu trong repo; PPTX giữ nguyên. Báo cáo DOCX là tài liệu riêng cần đồng
bộ nội dung với bộ số liệu mới trước khi phát hành.

### Phân tích artifact E4 đã tải

Nếu đã giải nén artifact `report-image` và `report-gate` cùng một run, xác minh
run ID/commit và đối chiếu summary với raw reports bằng:

```bash
python tests/analyze_e4_artifact.py \
  --artifact-dir "<thu_muc_report-image>" \
  --gate-artifact-dir "<thu_muc_report-gate>" \
  --out-json tests/results/metrics/e4_image_remediation.json \
  --out-md tests/results/metrics/e4_image_remediation.md
```

Script kiểm tra lại số lỗ hổng theo severity và số thành phần SBOM từ raw JSON,
lưu SHA-256, image ID/digest, Python/OS/architecture, tool version và DB
snapshot. Nếu thiếu bằng chứng per-scan hoặc có yếu tố khác nhau, kết quả được
đánh `limited` và `causal_attribution_allowed=false`.

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
