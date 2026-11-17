# Bằng chứng thí nghiệm live – 2026-11-16

Gói này là bộ bằng chứng mới nhất cho E1–E4, được thu từ GitHub Actions trên
commit `135606475be9d66842121135631d853a63c1e480`. Báo cáo E1/E2 được tính từ
observation và raw scanner report; không dùng `decisions.csv`, `findings.csv`
hoặc `runs.csv` làm dữ liệu phát hiện.

| Tệp | Nội dung |
|---|---|
| `e1_e2_live_observations.md` / `.json` | Kết quả scanner và gate trên 28 fixture lỗi, 10 thay đổi sạch và 8 negative control. JSON giữ kết quả từng fixture, finding và policy. |
| `e1_e2_source_manifest.json` | 47 observation của baseline ghép cặp và 46 fixture; kèm run URL, commit, SHA-256 observation/raw report, tool version và DB snapshot. |
| `e3_live_cache_comparison.md` / `.json` | 5 lượt cold + 5 lượt warm cùng commit, công cụ và Trivy/Grype DB snapshot; có median, IQR, p90, thời gian từng job và runner-minutes. |
| `e4_image_remediation.md` / `.json` | So sánh SBOM và vulnerability report trước/sau remediation; kèm cấu hình image, Dockerfile hash, raw report hashes và metadata DB. |
| `study_run_index.json` | Chỉ mục portable cho 58 lượt thu thập, gồm run URL, kết quả từng job và SHA-256 observation; không chứa đường dẫn file trên máy thu thập. |
| `PR_GATE_EVIDENCE.md` | Bằng chứng gate block/pass trên PR và ruleset/required checks hiện hành. |
| `SHA256SUMS.txt` | Hash của các tệp báo cáo trong gói. |

## Kết quả chính

- **E1:** scanner tìm finding đúng tool/rule ở 28/28 lỗi gieo cài; không có
  finding mới ở 0/10 thay đổi sạch và 0/8 negative control theo rule đích.
- **E2:** G1 có TP/FN/FP/TN = 28/0/0/10; G2 = 23/0/0/15. Cả hai đạt 100% block
  recall trên các trường hợp được kỳ vọng BLOCK; G2 đưa 5 lỗi mức cảnh báo sang
  WARN. G1 chặn 1/8 negative control; G2 chặn 0/8. G0 không có trường hợp kỳ vọng
  BLOCK nên recall không áp dụng.
- **E3:** wall median là 111 giây cold và 125 giây warm; warm chậm hơn 14 giây
  (12,61%) trong mẫu này. Đây là phép đo pip cache; scanner jobs vẫn chạy song
  song, không phải so sánh tuần tự.
- **E4:** bản ghi lỗ hổng Trivy giảm 4.486 → 206; CRITICAL 18 → 0; SBOM giảm
  22.943 → 2.856 thành phần. Hai image dùng cùng Python 3.13.18, Debian 13.7,
  amd64, Trivy 0.76.1 và DB snapshot; có thể quy kết quả cho toàn bộ thay đổi
  Dockerfile/image trong phép đo, không tách riêng đóng góp của từng thay đổi.

## Run nguồn

- E1/E2: baseline [43737561554](https://github.com/gialong611/DevSecOps_Project/actions/runs/43737561554); run URL cho từng fixture và hash nằm trong manifest.
- E3 cold: [43740564824](https://github.com/gialong611/DevSecOps_Project/actions/runs/43740564824), [43740783815](https://github.com/gialong611/DevSecOps_Project/actions/runs/43740783815), [43740991455](https://github.com/gialong611/DevSecOps_Project/actions/runs/43740991455), [43741199137](https://github.com/gialong611/DevSecOps_Project/actions/runs/43741199137), [43741402022](https://github.com/gialong611/DevSecOps_Project/actions/runs/43741402022).
- E3 warm: [43741626095](https://github.com/gialong611/DevSecOps_Project/actions/runs/43741626095), [43741895637](https://github.com/gialong611/DevSecOps_Project/actions/runs/43741895637), [43742113653](https://github.com/gialong611/DevSecOps_Project/actions/runs/43742113653), [43742355765](https://github.com/gialong611/DevSecOps_Project/actions/runs/43742355765), [43742614427](https://github.com/gialong611/DevSecOps_Project/actions/runs/43742614427).
- E4: [run 43743317883](https://github.com/gialong611/DevSecOps_Project/actions/runs/43743317883/attempts/1).

Raw reports vẫn được lưu trong artifacts của các run nguồn GitHub Actions;
GitHub có thể hết hạn lưu artifact. Các JSON trong repo giữ kết quả có thể đọc
bằng máy và hash để kiểm tra tính toàn vẹn.

## Giới hạn diễn giải

- Kết quả E1/E2 chỉ phản ánh bộ fixture gieo cài đã đo, không phải tỷ lệ phát
  hiện trong môi trường production.
- E3 dùng pip cache làm biến thay đổi; runner dùng chung có dao động tải. Các job
  `release` và `deploy-smoke` bị skip khi dispatch nên không có thời gian đo.
- E4 dùng image local, chưa có registry manifest digest. Bộ số CRITICAL `18 → 0`
  lấy từ hai raw report before/after của chính run E4, không phải từ một report
  scan đơn lẻ khác.
- T0 KEV/EPSS trong phần mô phỏng E4 không phải snapshot lịch sử CISA/FIRST.
