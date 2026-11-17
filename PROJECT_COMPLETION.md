# Trạng thái hoàn thiện đề tài 21

Cập nhật ngày 2026-11-16. Bộ bằng chứng E1–E4 mới nhất được tổng hợp tại
[`Code/DevSecOps/tests/results/metrics/live-evidence-2026-11-16/`](Code/DevSecOps/tests/results/metrics/live-evidence-2026-11-16/README.md), trên commit
`135606475be9d66842121135631d853a63c1e480`. Kết quả hiện đã có thể truy vết
đến run GitHub Actions, observation và SHA-256 của báo cáo nguồn.

## Kết quả thực nghiệm

| Thí nghiệm | Kết quả mới nhất | Cách diễn giải |
|---|---|---|
| E1 – scanner D/C/N | 28/28 lỗi gieo cài có finding mới khớp tool/rule; 0/10 thay đổi sạch có finding mới; 0/8 negative control có finding theo rule đích | Kết quả đo từ raw report; chỉ đại diện cho fixture đã gieo cài. |
| E2 – G1 | TP/FN/FP/TN = 28/0/0/10; block recall 28/28; blocker khớp rule đích 27/28; false-block trên C là 0/10 và trên N là 1/8 | G1 chặn mạnh hơn nhưng có một negative control bị chặn. |
| E2 – G2 | TP/FN/FP/TN = 23/0/0/15; block recall 23/23 trường hợp được kỳ vọng BLOCK; blocker khớp rule đích 22/23; false-block trên C và N là 0 | Trong 28 lỗi D, 23 lỗi được policy yêu cầu BLOCK và 5 lỗi được yêu cầu WARN; vì vậy không diễn giải 23/23 thành 28/28 lỗi bị chặn. |
| E2 – G0 | 0 trường hợp kỳ vọng BLOCK; recall không áp dụng; không chặn 8/8 negative control | G0 là baseline không chặn, không phải policy để đánh giá khả năng bắt lỗi nghiêm trọng. |
| E3 – thời gian CI | 5 lượt cold và 5 lượt warm trên cùng commit, cùng tool versions và snapshot Trivy/Grype. Wall median: 111s/125s; IQR: 3s/10s; p90: 115,8s/126,6s; tổng runner-minutes median: 3,45/3,63 | Warm chậm hơn cold 14s (12,61%) trong mẫu này. Chỉ pip cache thay đổi; scanner jobs vẫn song song. Không kết luận cache luôn làm chậm pipeline. |
| E4 – image/SBOM | Trivy: 4.486 → 206 bản ghi lỗ hổng (-95,4%); CRITICAL 18 → 0; HIGH 804 → 47. SBOM: 22.943 → 2.856 thành phần (-87,6%). Dockerfile controls: 0/4 → 4/4 | Cùng Python 3.13.18, Debian 13.7, amd64, Trivy 0.76.1 và DB snapshot. Kết luận áp dụng cho toàn bộ thay đổi Dockerfile/image. |

### Điều kiện và giới hạn

- E1/E2 gồm 38 mẫu D/C, 8 negative control N và baseline ghép theo đúng commit.
  Có 47 observation nguồn trong manifest; mỗi fixture được đối chiếu với raw
  scanner report và baseline tương ứng.
- E3 đo hiệu quả của pip cache trong workflow có các scanner chạy song song;
  không phải thí nghiệm chạy tuần tự. Một lượt warm-up bị loại. `release` và
  `deploy-smoke` bị skip khi dispatch, nên không có thời gian đo cho hai job này.
- E4 lấy số 18 CRITICAL trước và 0 sau từ hai raw report before/after của cùng
  run E4 `43743317883`. Đây là cặp image được quét với cùng tool/DB; không trộn
  với bảng severity của một report image đơn lẻ khác. Image ID là config digest
  cục bộ; chưa có registry manifest digest.
- T0 KEV/EPSS trong phần policy sensitivity của E4 là dữ liệu mô phỏng, không
  phải snapshot lịch sử CISA/FIRST.
- Raw artifacts của từng run còn nằm ở GitHub Actions và chịu thời hạn lưu của
  GitHub. JSON/manifest trong repo giữ kết quả, URL và hash để truy vết.

## Bằng chứng trên pull request và nhánh main

- Trong các lượt CI thuộc nhánh PR, lỗi D01 SQL injection bị G2 chặn ở
  [run 43729980295](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729980295).
  Sau khi hoàn nguyên fixture, gate pass ở
  [run 43730231762](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730231762).
- Ruleset **Protect main** đã được xác minh active trên `refs/heads/main`. Ruleset
  yêu cầu pull request và sáu status checks: DB snapshots, Python tests, security
  scans, IaC, image và gate. Lượt CI
  [43730524460](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730524460)
  cho thấy cả sáu check pass, nhưng PR #1 được merge lúc 15:35:38Z trước khi
  ruleset được tạo lúc 16:08:08Z. Vì thế chưa dùng PR #1 làm bằng chứng ruleset
  đã chặn merge.
- Ruleset yêu cầu 0 review, không yêu cầu nhánh cập nhật trước khi merge, chặn
  xóa nhánh và force push, và không cho bypass. Cấu hình được xác minh qua API;
  cần một PR mới sau thời điểm bật ruleset để chứng minh GitHub thực thi chặn
  merge khi required check pending/fail và cho merge khi tất cả pass.

## Mức hoàn thiện và phần còn lại

Phần pipeline và thực nghiệm E1–E4 đã có dữ liệu CI live, số lần lặp và nguồn
truy vết. So với bản trước, các tỷ lệ phát hiện không còn lấy từ `decisions.csv`
và E3 không còn là một lượt thăm dò. Đây là bằng chứng mạnh cho prototype và bộ
fixture, không phải ước lượng hiệu năng production.

Các cải thiện có giá trị tiếp theo:

1. Nếu muốn chứng minh mối liên kết với image phát hành, push hai image E4 vào
   registry và ghi manifest digest cạnh SBOM, scan report và provenance.
2. Mở rộng E3 bằng nhiều nhóm runner hoặc phép đo có kiểm soát mức song song;
   giữ cache, DB snapshot và tool versions được cố định.
3. Tiếp tục lưu artifact thô ngoài thời hạn retention của GitHub nếu cần tái
   phân tích dài hạn.

Không nên ghi đề tài “100/100” chỉ từ các số liệu này. Kết luận phù hợp là
pipeline đã chạy được, policy được thử bằng fixture live và required checks đã
được bật; giới hạn về production generalization, registry digest và mô phỏng
KEV/EPSS vẫn cần nêu trong báo cáo.

## Chạy lại thí nghiệm

Hướng dẫn dispatch, resume và phân tích artifact nằm trong
[`Code/DevSecOps/tests/README.md`](Code/DevSecOps/tests/README.md). Khi chạy lại,
ghim một commit cho toàn study và không gộp kết quả có khác tool version hoặc
snapshot DB.
