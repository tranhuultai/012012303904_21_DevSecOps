# Kịch bản demo và phân công trình bày

Tài liệu kèm theo báo cáo Đề tài 21 (Phụ lục B). Có hai phương án: **A** quay video khoảng 11 phút, **B** thuyết trình trực tiếp 18-19 phút kèm demo. Slide: `PPTX/DeTai21_DevSecOps.pptx`, ghi chú người nói nằm trong phần Notes của từng slide.

## 1. Phân công

| Thành viên | GitHub | Phụ trách chính | Phần trình bày |
| --- | --- | --- | --- |
| Trần Hữu Tài | `tranhuultai` | Hạ tầng (Terraform, Kubernetes), Dockerfile, chuỗi cung ứng (release, ký image, deploy-smoke), E4, chi phí, dọn tài nguyên | Luồng lỗi PR, release, E4, đánh giá chung, rủi ro và giải pháp |
| Đỗ Ngọc Duy | `duy13-computer` | Ứng dụng FastAPI, các lớp quét, workflow CI, chuẩn hóa findings, tóm tắt PR | Repo, năm lớp quét, kiến trúc, luồng findings, ngoại lệ, luồng PR sạch |
| Hoàng Gia Long | `gialong611` | Chính sách gate Rego, bộ đáp án, E1-E3, phân tích dữ liệu, tổng hợp báo cáo | Bài toán, mô hình nghiên cứu, bộ lỗi gieo cài, kết quả E1-E3, kết luận |

## 2. Chuẩn bị trước buổi báo cáo

- [ ] Mở sẵn các tab: trang repo; tab Actions; [PR #21](https://github.com/tranhuultai/012012303904_21_DevSecOps/pull/21); run [41699096052](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699096052) (BLOCK), [41699668185](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699668185) (PASS), [41700761072](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41700761072) (push `main` có release, deploy-smoke); trang Packages của image; `Code/DevSecOps/tests/analysis.ipynb`.
- [ ] Tạo sẵn hai nhánh demo (mục 5) và mở PR trước 10-15 phút, để run đầu tiên đã xong khi lên trình bày.
- [ ] `gh auth status` đăng nhập đúng tài khoản; tắt thông báo; phóng chữ trình duyệt và terminal 125-150 %.
- [ ] Quay video: 1920x1080, thu âm riêng từng người nếu cần, cắt ghép theo mốc thời gian ở mục 3.
- [ ] Mỗi người tập phần mình ít nhất hai lần, bấm giờ; đọc `Extra/HUONG_DAN_TRIEN_KHAI.md` để trả lời câu hỏi về triển khai, chi phí, rủi ro.

## 3. Phương án A: video khoảng 11 phút

| Thời điểm | Nội dung và thao tác | Người trình bày |
| --- | --- | --- |
| 0:00-1:00 | Bài toán, câu hỏi nghiên cứu, kiến trúc mục tiêu (slide 2, 7) | Hoàng Gia Long |
| 1:00-3:00 | Kho mã, baseline, workflow năm lớp quét, ba chính sách gate | Đỗ Ngọc Duy |
| 3:00-5:00 | Luồng bình thường: PR thay đổi sạch, mọi job xanh, gate PASS | Đỗ Ngọc Duy |
| 5:00-7:30 | Luồng lỗi: PR mở SSH cho `0.0.0.0/0`, gate BLOCK vì `CKV_AWS_24`, đẩy commit sửa, gate PASS | Trần Hữu Tài |
| 7:30-8:30 | Release: digest trên GHCR, `cosign verify`, deploy-smoke gọi `/health`; E4 trước - sau | Trần Hữu Tài |
| 8:30-10:30 | Kết quả E1-E3 từ notebook: recall, chặn nhầm, cảnh báo, thời gian | Hoàng Gia Long |
| 10:30-11:30 | Đề xuất chính sách, chi phí, rủi ro còn lại, kết luận | Hoàng Gia Long |

### Thao tác chi tiết

**1:00-3:00 (Duy).** Mở cây thư mục `Code/DevSecOps/`: `src/` (ứng dụng), `infra/` và `deploy/` (Terraform, Kubernetes), `rules/`, `policy/g0|g1|g2`. Mở `.github/workflows/ci.yml`, chỉ năm job `test`, `security-scan`, `iac`, `image`, `gate`; nhấn mạnh quyền mặc định `contents: read` và action ghim SHA. Mở `policy/g2/` và nói ba điều kiện chặn: tác động cao, phát hiện đáng tin, sửa được ngay.

**3:00-5:00 (Duy).** Mở PR thay đổi sạch (nhánh `demo/clean`, mục 5). Ở tab Checks, chỉ các job chạy song song rồi đến `gate`. Mở Summary của run: chế độ delta, 0 finding mới thuộc diện chặn, kết quả PASS.

**5:00-7:30 (Tài).** Mở PR luồng lỗi (nhánh `demo/ssh-open`). Ở Summary: gate BLOCK, finding mới `CKV_AWS_24` (Checkov) trỏ vào `infra/security_groups.tf`, kèm cảnh báo WARN của Trivy `AWS-0107` cho cùng lỗi (Trivy xếp lỗi này vào diện cảnh báo, Checkov vào diện chặn). Nếu ruleset đã bật required check thì chỉ nút merge bị khóa. Đẩy commit sửa, chờ run mới (khoảng 1,5-2 phút; có thể cắt ghép trong video), mở Summary: PASS.

**7:30-8:30 (Tài).** Mở run push `main` 41700761072: job `release` in digest `ghcr.io/.../devsecops@sha256:...`; job `deploy-smoke` có bước `cosign verify` thành công và lệnh `curl /health` trả kết quả. Mở hình `tests/results/figures/e4_before_after.png`: 517 xuống 118 gói, 1.532 xuống 85 CVE (Trivy).

**8:30-10:30 (Long).** Mở `analysis.ipynb` (xem trực tiếp trên GitHub được): E1 từng công cụ bắt tối đa 13/28, kết hợp 28/28; E2 G1 chế độ full chặn nhầm 10/10 thay đổi sạch, G2 0/10, ở chế độ delta G1 cũng 0/10; E3 song song nhanh hơn khoảng 10 %, phút runner tăng khoảng 2,2 lần, cache không giúp.

**10:30-11:30 (Long).** Slide 17 và 18: chính sách G2 chấm delta, chi phí 0 đồng (ước tính 4,11 USD/tháng nếu là repo riêng), rủi ro mức Cao về required check và cách khắc phục.

## 4. Phương án B: thuyết trình trực tiếp khoảng 19 phút

| Slide | Nội dung | Người nói | Thời lượng |
| --- | --- | --- | --- |
| 1-3 | Mở đầu, bài toán, mục tiêu | Hoàng Gia Long | 2:15 |
| 4-5 | Năm lớp quét, đánh giá mức nguy hiểm của CVE | Đỗ Ngọc Duy | 2:00 |
| 6 | Mô hình nghiên cứu và giả thuyết | Hoàng Gia Long | 1:00 |
| 7-9 | Kiến trúc, luồng findings, ba chính sách gate, ngoại lệ | Đỗ Ngọc Duy | 3:00 |
| 10-13 | Bộ lỗi gieo cài, kết quả E1, E2, E3 | Hoàng Gia Long | 3:45 |
| 14 | E4: image trước và sau khắc phục | Trần Hữu Tài | 1:00 |
| 15 | **Demo trực tiếp**: PR bị chặn, đẩy commit sửa, gate qua | Trần Hữu Tài | 3:00 |
| 16-17 | Đánh giá giả thuyết và chi phí, bốn giải pháp đề xuất | Trần Hữu Tài | 2:00 |
| 18 | Kết luận | Hoàng Gia Long | 0:45 |

Cách chạy demo ở slide 15 để không phải chờ: PR `demo/ssh-open` đã mở và BLOCK từ trước. Lên slide 15, mở Summary BLOCK, đẩy commit sửa ngay, rồi nói slide 16 trong lúc run chạy; quay lại tab PR khi gate PASS. Thời gian còn lại dành cho hỏi đáp.

## 5. Chuẩn bị nhánh demo

Chạy từ thư mục gốc của repo.

```bash
# Luồng bình thường: thay đổi sạch C02 (thêm một docstring)
git switch -c demo/clean origin/main
git apply Code/DevSecOps/ground_truth/patches/C02_add_docstrings.patch
git commit -am "docs(app): add a docstring to the root endpoint"
git push -u origin demo/clean
gh pr create --base main --head demo/clean --title "docs(app): add a docstring to the root endpoint" --body "Demo: thay đổi sạch, gate kỳ vọng PASS."

# Luồng lỗi: mở SSH cho 0.0.0.0/0
git switch -c demo/ssh-open origin/main
# Thêm khối sau vào resource "aws_security_group" "alb" trong
# Code/DevSecOps/infra/security_groups.tf, ngay sau khối ingress đầu tiên:
#   ingress {
#     description = "SSH tu Internet"
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
git commit -am "test(demo): open SSH to 0.0.0.0/0"
git push -u origin demo/ssh-open
gh pr create --base main --head demo/ssh-open --title "test(demo): open SSH to 0.0.0.0/0" --body "Demo: gate kỳ vọng BLOCK vì CKV_AWS_24."

# Lúc demo: sửa bằng cách hoàn tác commit lỗi
git revert --no-edit HEAD && git push
```

Sau buổi báo cáo: đóng hai PR demo không merge và xóa nhánh (`git push origin --delete demo/clean demo/ssh-open`).

## 6. Dự phòng

- Mạng chậm hoặc runner xếp hàng lâu: dùng run có sẵn của PR #21, [41699096052](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699096052) (BLOCK) và [41699668185](https://github.com/tranhuultai/012012303904_21_DevSecOps/actions/runs/41699668185) (PASS). Báo cáo gate của hai run lưu tại `Code/DevSecOps/tests/results/raw/demo_20261103_pr21/`.
- Không mở được GitHub: trình bày bằng slide 11-15 và video quay sẵn theo phương án A.
- Một thành viên vắng: người phụ trách phần liền kề nói thay, theo ghi chú trong Notes của slide.
