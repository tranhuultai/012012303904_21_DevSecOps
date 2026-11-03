# Trạng thái hoàn thiện đề tài 21

Cập nhật: 2026-11-01. Tài liệu đối chiếu rubric với mã nguồn và artifact CI
đã tải; điểm là tự đánh giá nội bộ, không phải điểm chính thức của giảng viên.

## Trạng thái hiện tại

- Workflow `DevSecOps CI` chạy thành công trên commit
  `cbcef8e32d5b007229be5e424409e8ee00fe278e` ở
  [run #13](https://github.com/gialong611/DevSecOps_Project/actions/runs/41288998886).
  Các job Python tests, security scan, IaC, image, gate, release và deploy-smoke
  đều thành công. Artifact `report-scan`, `report-iac`, `report-image`,
  `report-gate` và `sbom` đã được tải và phân tích.
- Gate trả `WARN`: 275 finding chuẩn hóa, 0 blocker và 30 cảnh báo (15 HIGH,
  15 MEDIUM). Ngưỡng 20 áp dụng cho PR; run #13 là `push`, nên số này là tín
  hiệu về nhiễu baseline, chưa phải phép đo PR bị tê liệt.
- Raw scan gồm Trivy 1 finding, Checkov 92 failed checks và Grype 182 matches;
  Semgrep, Gitleaks và Trivy config không có finding. `checkov.json` trong
  artifact là stream gồm 3 JSON document liền nhau: loader của dự án đọc được,
  nhưng `json.load` tiêu chuẩn dừng ở dòng 6354 vì `Extra data`. Workflow local
  hiện giữ stream gốc tại `checkov.stream.json` và tạo `checkov.json` dạng JSON
  array; cần CI run tiếp theo xác nhận thay đổi này.
- Cảnh báo MEDIUM được truy về 5 Python, 5 pip, 2 pytest và 3 Starlette. Working
  tree đã nâng Python lên 3.13.18, pip lên 26.2.2 và pytest lên 9.0.3; đây là
  mục tiêu remediation cho 12 cảnh báo, chưa phải kết quả scan đã xác nhận.
  Ba cảnh báo Starlette được giữ lại chờ đánh giá tương thích major version.
  Nếu 12 cảnh báo biến mất và không phát sinh cảnh báo mới, số cảnh báo dự kiến
  là 18; phải ghi nhận từ scan mới trước khi kết luận.
- E4 raw artifact ghi nhận Trivy giảm từ 4.721 xuống 188 vulnerability
  records (-4.533): CRITICAL 21→0, HIGH 531→52, MEDIUM 2.037→71, LOW
  2.030→64, UNKNOWN 102→1. SBOM giảm từ 22.921 xuống 2.860 package
  (-20.061). Cả hai scan dùng Trivy 0.76.1, cùng DB snapshot
  `2026-11-01 07:08:40 UTC`, Debian 13.7 và amd64. Python khác phiên bản
  (3.12.15 trước, 3.12.16 sau), nên số liệu là delta quan sát được nhưng không
  quy riêng cho từng kiểm soát Dockerfile. Artifact có image ID cục bộ nhưng
  không có `RepoDigests`. Dockerfile mẫu đã được đồng bộ Python 3.13.18 trong
  working tree để lượt sau giảm yếu tố gây nhiễu.
- E3 run #13 ghi ba job scan song song: 28s (security-scan), 37s (IaC), 171s
  (image). Đường găng của giai đoạn này là 171s; tổng tuần tự 236s chỉ là phép
  cộng ước tính, không phải workflow chạy tuần tự đã đo. Run #11 có 148s trên
  commit khác nên không gộp thành lặp có kiểm soát. Chưa có lặp cache/song song.
- E1/E2 chưa có đủ observation raw cho toàn bộ D01–D28, C01–C10 và N01–N08;
  hiện chưa kết luận recall, scanner false-positive rate hay gate false-block
  rate từ CI. DOCX/PPTX chưa được sinh lại từ các số liệu run #13.

## Tự đánh giá theo rubric

| Thành phần | Điểm tối đa | Ước tính | Bằng chứng còn thiếu để đạt tối đa |
|---|---:|---:|---|
| Cơ sở lý thuyết và câu hỏi nghiên cứu | 15 | 14 | Hoàn thiện ánh xạ chuẩn cho toàn bộ nhóm IaC và xác minh phiên bản benchmark. |
| Thiết kế kiến trúc và phương pháp | 15 | 14 | Bổ sung sơ đồ luồng dữ liệu của finding qua từng scanner, normalizer và gate. |
| Mức hoàn thiện thực nghiệm | 25 | 17 | Chạy đủ D/C/N; xác minh commit lỗi bị chặn và bản vá vượt gate; xử lý baseline warning theo kết quả scan mới. |
| Dữ liệu đo và phân tích | 20 | 14 | Có E4 raw và một E3 traceable; cần nhiều lượt E3 có kiểm soát cùng commit và phân tích đủ D/C/N. |
| An toàn bảo mật và quản trị chi phí | 10 | 8 | Xác minh provenance độc lập; ghi nguồn và ngày của đơn giá runner. |
| Mã nguồn, tài liệu và khả năng tái lập | 10 | 7 | Cập nhật DOCX/PPTX, chạy lại các hướng dẫn và lưu CI evidence sau thay đổi. |
| Báo cáo trình bày và phản biện | 5 | 3 | Chuẩn bị demo lỗi/bản vá và câu trả lời gắn với metric đo được. |
| **Tổng tự đánh giá** | **100** | **77** | **Ước tính nội bộ; chưa phải điểm chính thức.** |

## Việc cần hoàn thành tiếp

- [x] Có run baseline end-to-end thành công và lưu artifact.
- [x] Tải, giải nén và phân tích raw artifact run #13; ghi số tuyệt đối E4,
  image ID, DB snapshot, thời gian E3 và phân loại 15 cảnh báo MEDIUM.
- [x] Xác định nguyên nhân `json.load` báo `Extra data`: artifact Checkov là
  stream 3 JSON document; cập nhật workflow local để giữ stream và xuất array.
- [ ] Chạy CI cho các thay đổi Python/pip/pytest và Checkov; ghi số MEDIUM còn
  lại thực tế, warning count, trạng thái gate và compatibility test.
- [ ] Xác minh patch D09/D10/C04/D12 áp dụng đúng trên commit mới, sau đó chạy
  đủ baseline, D01–D28, C01–C10 và N01–N08 với cùng tool versions và Trivy DB
  snapshot. Tổng hợp bằng `tests/analyze_fixture_observations.py`.
- [ ] Lặp E3 tối thiểu 5 lần cho mỗi cấu hình cache/song song, trên cùng commit;
  báo median/IQR, thời gian mỗi job, đường găng và runner-minutes.
- [ ] Lặp E4 khi Python trước/sau giống nhau; lưu report Trivy, SBOM Syft,
  digest có thể truy vết và metadata DB.
- [ ] Xác minh chữ ký image và provenance độc lập; lưu lệnh và kết quả.
- [ ] Ghi đơn giá runner có nguồn và ngày tra cứu; hoàn thiện ước tính chi phí.
- [ ] Cập nhật DOCX/PPTX từ số liệu đã kiểm tra và render để rà bố cục.
- [ ] Chấm lại rubric khi artifact và tài liệu đã cập nhật.

## Vị trí mã nguồn và bằng chứng

- Workflow CI: `.github/workflows/ci.yml`
- Fixture và ground truth: `Code/DevSecOps/ground_truth/`
- Script thu observation: `Code/DevSecOps/tests/record_*`
- Script tổng hợp fixture: `Code/DevSecOps/tests/analyze_fixture_observations.py`
- Metrics và triage: `Code/DevSecOps/tests/results/metrics/`
- Hướng dẫn thu thập: `Code/DevSecOps/tests/README.md`
