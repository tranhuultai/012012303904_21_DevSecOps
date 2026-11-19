# Trạng thái hoàn thiện đề tài 21

Cập nhật ngày 2026-11-19. Bộ bằng chứng E1-E4 của đợt đo chính thức được tổng hợp tại
[`Code/DevSecOps/tests/results/metrics/live-evidence-2026-11-16/`](Code/DevSecOps/tests/results/metrics/live-evidence-2026-11-16/README.md).
Đợt đo chạy ngày 15/11/2026 trên kho thực nghiệm `gialong611/DevSecOps_Project`, commit
`135606475be9d66842121135631d853a63c1e480`; commit này cũng có trong kho nộp bài và dữ liệu được
đồng bộ về qua PR #30. Kết quả có thể truy vết đến run GitHub Actions, observation và SHA-256 của
báo cáo nguồn. Báo cáo và slide nộp: `DOCX/DeTai21_DevSecOps.docx`, `PPTX/DeTai21_DevSecOps.pptx`.

## Kết quả thực nghiệm

| Thí nghiệm | Kết quả mới nhất | Cách diễn giải |
|---|---|---|
| E1 - scanner D/C/N | 28/28 lỗi gieo cài có finding mới khớp tool/rule; 0/10 thay đổi sạch có finding mới; 0/8 mẫu đối chứng có finding theo rule đích | Kết quả đo từ raw report; chỉ đại diện cho fixture đã gieo cài. Luật Semgrep và luật workflow do nhóm tự viết nên kết quả lạc quan. |
| E2 - chế độ full | G1 chặn 28/28 lỗi D nhưng chặn nhầm 10/10 thay đổi sạch và 8/8 mẫu đối chứng; G2 chặn 23/23 lỗi tầng BLOCK, không chặn nhầm (0/10, 0/8); G0 không chặn | Chế độ full là quyết định thật của gate. G1 chặn nhầm vì baseline đã có nhiều finding từ MEDIUM. |
| E2 - chế độ delta, G1 | TP/FN/FP/TN = 28/0/0/10; blocker khớp rule đích 27/28; chặn nhầm C 0/10, N 1/8 | Khi chỉ chấm blocker mới, G1 không còn chặn nhầm thay đổi sạch. |
| E2 - chế độ delta, G2 | TP/FN/FP/TN = 23/0/0/15; blocker khớp rule đích 22/23; chặn nhầm C và N là 0 | Trong 28 lỗi D, 23 lỗi được policy yêu cầu BLOCK và 5 lỗi được yêu cầu WARN; không diễn giải 23/23 thành 28/28 lỗi bị chặn. |
| E3 - thời gian CI | 5 lượt cold và 5 lượt warm trên cùng commit, cùng tool versions và snapshot Trivy/Grype. Trung vị: 111 s/125 s; IQR: 3 s/10 s; p90: 115,8 s/126,6 s; phút runner trung vị: 3,45/3,63 | Warm chậm hơn cold 14 s (12,61 %) trong mẫu này. Chỉ pip cache thay đổi; các job quét vẫn song song. Không kết luận cache luôn làm chậm pipeline. |
| E4 - image/SBOM | Trivy: 4.486 → 206 bản ghi lỗ hổng (-95,4 %); CRITICAL 18 → 0; HIGH 804 → 47. SBOM: 22.943 → 2.856 thành phần (-87,6 %). Kiểm soát Dockerfile: 0/4 → 4/4 | Cùng Python 3.13.18, Debian 13.7, amd64, Trivy 0.76.1 và DB snapshot. Kết luận áp dụng cho toàn bộ thay đổi Dockerfile/image. |

Phần đợt chính thức không đo (so sánh chạy tuần tự và song song; kích thước image, CVE có bản vá)
lấy từ đợt sơ bộ 03-04/11/2026 trên kho nộp bài (`tests/results/metrics/so_lieu_bao_cao.csv`).

### Điều kiện và giới hạn

- E1/E2 gồm 38 mẫu D/C, 8 mẫu đối chứng N và baseline ghép theo đúng commit.
  Có 47 observation nguồn trong manifest; mỗi fixture được đối chiếu với raw
  scanner report và baseline tương ứng. Mỗi mẫu chỉ chạy một lượt.
- E3 đo hiệu quả của pip cache trong workflow có các job quét chạy song song;
  không phải thí nghiệm chạy tuần tự. Một lượt làm nóng bị loại. `release` và
  `deploy-smoke` bị bỏ qua khi dispatch, nên không có thời gian đo cho hai job này.
- E4 lấy số 18 CRITICAL trước và 0 sau từ hai raw report before/after của cùng
  run E4 `43743317883`. Image ID là config digest cục bộ; chưa có registry manifest digest.
- KEV/EPSS trong phần độ nhạy chính sách của E4 là dữ liệu mô phỏng, không
  phải snapshot lịch sử CISA/FIRST.
- Raw artifacts của từng run nằm ở GitHub Actions và chịu thời hạn lưu của
  GitHub. JSON/manifest trong repo giữ kết quả, URL và hash để truy vết.
- `SHA256SUMS.txt` của gói bằng chứng băm 8 tệp ở dạng CRLF và 2 tệp ở dạng LF (xem README).

## Bằng chứng trên pull request và nhánh main

- Kho nộp bài: PR #21 (03/11/2026) mở SSH cho `0.0.0.0/0` bị G2 chặn đúng `CKV_AWS_24`
  ([run 41699096052](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699096052))
  và pass sau khi gỡ luật
  ([run 41699668185](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699668185)).
- Kho thực nghiệm: lỗi D01 SQL injection bị G2 chặn ở
  [run 43729980295](https://github.com/gialong611/DevSecOps_Project/actions/runs/43729980295) và
  pass sau khi hoàn nguyên ở
  [run 43730231762](https://github.com/gialong611/DevSecOps_Project/actions/runs/43730231762).
- Ruleset `main` của kho nộp bài (đọc qua API ngày 19/11/2026): active; bắt buộc pull request với
  1 lượt duyệt của chủ sở hữu mã, bỏ duyệt cũ khi có commit mới, duyệt lần push cuối, giải quyết hết
  thảo luận; bắt buộc check `gate (Conftest Rego)`; chặn xóa nhánh và force push. Hai tài khoản có
  quyền bỏ qua (`always`), nên PR bị BLOCK vẫn có thể được hai tài khoản này merge.
- `PR_GATE_EVIDENCE.md` trong gói bằng chứng mô tả ruleset **Protect main** của kho thực nghiệm
  (sáu required check, 0 review, không bypass), không phải của kho nộp bài.

## Kiểm chứng phần AWS

Không có tài khoản AWS nên Terraform không được `apply`. Workflow `iac-validate.yml` chạy
`terraform validate`, `terraform test` với provider giả lập và chạy thật script khởi động EC2 trên
runner Ubuntu 24.04; lần chạy
[44126623520](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/44126623520)
(17/11/2026) đạt cả hai job. Phép kiểm này chưa chứng minh việc tạo tài nguyên thật, ALB, chứng chỉ,
DNS và đường mạng ra Internet.

## Mức hoàn thiện và phần còn lại

Phần pipeline và thực nghiệm E1-E4 đã có dữ liệu CI live, số lần lặp và nguồn
truy vết. Đây là bằng chứng cho prototype và bộ fixture, không phải ước lượng
hiệu năng production.

Các việc còn lại đã biết:

1. Gỡ quyền bỏ qua ruleset của hai tài khoản để gate thật sự khóa merge.
2. Security group của ứng dụng chỉ cho egress cổng 5432 trong VPC, nên EC2 không tải được Docker,
   cosign và image từ GHCR khi triển khai thật. Cần mở egress 443 kèm ngoại lệ có thời hạn hoặc dùng
   registry trong VPC, và thêm bài test cho điều kiện này.
3. Sau lần đồng bộ ngày 17/11/2026, `ci.yml` không còn bước lọc delta cho pull request, không tải
   KEV/EPSS lúc chạy và không thử lại khi tải công cụ. `tools/delta_findings.py` và
   `tools/download_release.sh` vẫn còn trong kho nhưng `ci.yml` không gọi; `tools/fetch_kev_epss.py`
   chỉ còn được dùng trong `experiments.yml`.
4. Push hai image E4 vào registry và ghi manifest digest cạnh SBOM, scan report và provenance;
   lưu artifact thô ngoài thời hạn lưu của GitHub nếu cần tái phân tích dài hạn.

Không nên ghi đề tài "100/100" chỉ từ các số liệu này. Kết luận phù hợp là
pipeline đã chạy được, policy được thử bằng fixture live và required check đã
được bật; giới hạn về production generalization, registry digest và mô phỏng
KEV/EPSS vẫn được nêu trong báo cáo.

## Chạy lại thí nghiệm

Hướng dẫn dispatch, resume và phân tích artifact nằm trong
[`Code/DevSecOps/tests/README.md`](Code/DevSecOps/tests/README.md). Khi chạy lại,
ghim một commit cho toàn study và không gộp kết quả có khác tool version hoặc
snapshot DB.
