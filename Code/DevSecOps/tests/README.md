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

## Mục 2b. Giả thuyết (viết ngày 03/11/2026, trước lần chạy thực nghiệm chính thức; không sửa sau khi có số liệu)
- H1: Không công cụ đơn lẻ nào đạt recall từ 50% trên 28 lỗi, nhưng 5 lớp kết hợp đạt ít nhất 85%.
- H2: G1 chặn nhầm ít nhất một nửa số thay đổi sạch; G2 không chặn nhầm thay đổi sạch nào và chặn mọi lỗi tầng BLOCK.
- H3: Cấu hình song song có cache (C3) rút ngắn thời gian trung vị ít nhất 30% so với tuần tự không cache (C1).
- H4: Image sau khắc phục giảm ít nhất một nửa số CVE CRITICAL/HIGH có bản vá và nhẹ hơn image trước.

## Mục 3. Dữ liệu và cách thu

- E1, E2, E4: workflow `experiments.yml` chạy ma trận 47 mẫu (BASE, D01–D28, C01–C10, N01–N08) trên
  commit của tag `gt-v1`. Mỗi mẫu áp đúng một patch rồi chạy `run_scans.sh` với cùng phiên bản công
  cụ như `ci.yml`; Semgrep chạy tách luật tự viết và bộ luật registry. Job `aggregate` lấy KEV/EPSS
  tại thời điểm chấm, chạy `collect_experiment.py` và `eval_policies.py` (Conftest thật cho G0/G1/G2,
  chế độ full và delta), job `e4-image` build mỗi image ba lần rồi quét SBOM và lỗ hổng.
- E3: workflow `e3-orchestrate.yml` chạy xen kẽ C1 (tuần tự, không cache), C2 (song song, không cache),
  C3 (song song, cache pip, Trivy DB, binary công cụ) trên cùng một SHA; thời gian lấy từ API jobs,
  không tính thời gian xếp hàng. Mỗi lần điều phối có nhãn lượt chạy và khóa cache riêng, nên lượt đầu
  của C3 luôn là cache lạnh và được loại khi tính trung vị.
- Dữ liệu thô được lưu tại `results/raw/exp_<ngày>_<run_id>/` và `results/raw/e3_<ngày>_<run_id>/`:
  `findings_all.csv`, `decisions.csv`, `samples.csv`, `scan_runs.csv`, `consistency.json`,
  `e4_images.csv`, `kev/`, `samples/<mẫu>/`, `e4/` (SBOM Syft, báo cáo Trivy và Grype của hai image,
  nén gzip) và `runs.csv`, `jobs.csv`, `meta.json`. URL run nằm trong `samples.csv`, `runs.csv` và các
  `meta.json`; báo cáo thô của từng công cụ theo mẫu nằm trong artifact của run (giữ 90 ngày).
- `results/raw/demo_20261103_pr21/`: báo cáo gate của PR #21 khi commit lỗi bị chặn (`block/`) và sau
  khi sửa (`pass/`), kèm `run.json` lấy từ API.
- `analyze_results.py` (hoặc `analysis.ipynb`) sinh `results/metrics/*.csv`, `results/figures/*.png`
  và `results/metrics/so_lieu_bao_cao.csv`; số nào chưa có nguồn được ghi `CHUA_DO`.
- Finding được tính là phát hiện đúng khi là finding mới so với baseline, có rule ID thuộc
  `accepted_rule_ids` và trỏ đúng tệp đích trong `ground_truth.csv`. Recall trình bày phân số trước,
  phần trăm sau; không dùng accuracy.

## Mục 4. Ghi chú khi đọc số liệu

- `e1_recall_by_tool.csv`: `new_outside_key_d`, `new_on_n`, `new_on_c` đếm theo công cụ các finding mới
  không thuộc đáp án trên mẫu D và mọi finding mới trên N, trên C. Đây là ứng viên báo nhầm, chưa
  triage; kết quả triage của nhóm lưu ở `results/triage/`.
- `e1_detection_by_defect.csv` có quyết định G1/G2 của từng lỗi cạnh `expected_g2`. D10 là mẫu duy nhất
  lệch tầng: lỗi gieo là CVE-2023-45803 (MEDIUM, kỳ vọng WARN) nhưng bản urllib3 cũ còn CVE HIGH có bản
  vá (ví dụ CVE-2025-66418) nên G2 trả BLOCK.
- N04 (urllib3 2.6.0) có 5 CVE HIGH theo Trivy DB 2026-11-03 nên bị G2 chặn; đây là mẫu N duy nhất bị
  G2 chặn (`controls_blocked`).
- Baseline là trạng thái sau khi sửa của mọi lỗi D: G2 full trả WARN với 96 cảnh báo, không chặn
  (`E2_G2_BASELINE_FULL`). Minh chứng chặn rồi qua trên CI thật: PR #21 (`demo_20261103_pr21/`).
- Cùng lỗi mở cổng 22, Checkov báo `CKV_AWS_24` (thuộc danh mục chặn) còn Trivy báo `AWS-0107` (chỉ
  WARN); chính sách giữ nguyên như lúc đóng băng ở `gt-v1`.
- `e1_scan_timing.csv`: thời gian từng bước quét trong một runner, không gồm cài công cụ;
  `e3_jobs.csv`: thời gian từng job của E3. Bộ luật registry `p/python` của Semgrep tải lúc chạy nên
  không ghim được phiên bản.

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
