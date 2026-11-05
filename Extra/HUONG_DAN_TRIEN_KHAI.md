# Hướng dẫn triển khai, tái lập và dọn tài nguyên

Tài liệu kèm theo báo cáo Đề tài 21 (Phụ lục A và mục 2.4 của báo cáo). Các lệnh chạy từ thư mục gốc của repo, trừ khi ghi khác.

## 1. Phạm vi

| Thành phần | Có triển khai thật? | Ghi chú |
| --- | --- | --- |
| Đường ống CI trên GitHub Actions | Có | `.github/workflows/ci.yml` |
| Image ứng dụng trên GHCR | Có, khi push `main` | `ghcr.io/<owner>/devsecops`, tham chiếu theo digest |
| Cụm Kubernetes | Có, cụm `kind` tạm trong runner | Mất khi job kết thúc |
| Hạ tầng AWS (Terraform): VPC, S3, IAM, RDS, EC2 chạy ứng dụng, ALB HTTPS | Không | Quét tĩnh; kiểm bằng `terraform validate` và `terraform test` với provider giả lập; chạy thử script khởi động EC2 trên máy Ubuntu của GitHub (mục 4a). Không `apply`, không phát sinh chi phí |

## 2. Yêu cầu

- Tài khoản GitHub, Git, Python 3.13, GitHub CLI (`gh`) đã đăng nhập.
- Muốn quét tại máy: cài các công cụ đúng phiên bản trong [`TOOL_VERSIONS.md`](TOOL_VERSIONS.md).
- Không cần tài khoản AWS.

## 3. Triển khai đường ống

1. Fork hoặc clone repo, bật GitHub Actions (tab **Actions**).
2. **Settings > Actions > General > Workflow permissions**: để mặc định *Read repository contents*. Các job cần thêm quyền (`release`: `packages: write`, `id-token: write`, `attestations: write`; `gate`: `actions: read`) đã tự khai báo trong workflow.
3. **Settings > Rules > Rulesets**, tạo ruleset cho nhánh `main`:
   - Require a pull request before merging, bật *Require review from Code Owners*.
   - Block force pushes, Restrict deletions.
   - Require status checks to pass, thêm check **`gate (Conftest Rego)`**.
   - Không thêm ai vào *Bypass list*, kể cả chủ repo. Thiếu bước này thì PR bị gate chặn vẫn merge được (rủi ro mức Cao ở mục 7).
4. Mở một pull request bất kỳ vào `main`. Các job `test`, `security-scan`, `iac`, `image` chạy song song, sau đó `gate`. Kết quả gate (PASS/BLOCK, danh sách finding mới) xem ở mục **Summary** của lần chạy.

Chính sách gate mặc định là G2 (`CONTEST_POLICY: g2` trong `ci.yml`). Ngoại lệ khai báo trong `Code/DevSecOps/security/exceptions.yaml`, bắt buộc có người chịu trách nhiệm, người duyệt khác người đề xuất và ngày hết hạn (CRITICAL tối đa 7 ngày, HIGH 30 ngày, MEDIUM/LOW 90 ngày). Secret không được miễn.

## 4. Phát hành và kiểm chứng image

Khi push vào `main` và gate PASS:

1. Job `release` build image, đẩy lên GHCR, lấy digest, ký keyless bằng Cosign, đính kèm SBOM CycloneDX và provenance.
2. Job `deploy-smoke` kiểm chữ ký, tạo cụm `kind`, triển khai manifest trong `Code/DevSecOps/deploy/` và gọi `/health`.

Kiểm chữ ký thủ công (thay `<digest>` bằng digest trong log job `release`):

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/<owner>/<repo>/.github/workflows/.+" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/<owner>/devsecops@sha256:<digest>

gh attestation verify oci://ghcr.io/<owner>/devsecops@sha256:<digest> --owner <owner>
```

## 4a. Triển khai lên AWS và cách kiểm chứng khi chưa có tài khoản

### Kiến trúc trên AWS

`infra/` mô tả đủ đường đi của một yêu cầu: Internet -> ALB (chỉ HTTPS, TLS 1.3, `compute.tf`) -> EC2 Ubuntu 24.04 (`compute.tf`) -> container ứng dụng; RDS PostgreSQL trong subnet riêng; S3 và IAM role chỉ đọc một bucket. Khi khởi động, EC2 chạy `infra/scripts/ec2_bootstrap.sh`: kiểm chữ ký image bằng cosign (chỉ chấp nhận chữ ký do workflow của repo tạo), sai thì dừng, đúng thì chạy container với user không phải root, hệ thống tệp chỉ đọc, bỏ mọi capability, rồi chờ `/health`.

### Kiểm chứng không cần tài khoản AWS (0 đồng)

Workflow `.github/workflows/iac-validate.yml` chạy khi có PR sửa `infra/`, hoặc bấm Run workflow:

| Job | Kiểm gì | Chứng minh được |
| --- | --- | --- |
| `terraform validate + test` | `terraform fmt`, `init` (không backend, không credentials), `validate`, `terraform test` với provider giả lập (`infra/tests/infra.tftest.hcl`) | Cấu hình đúng cú pháp và đúng schema của provider AWS 5.100.0; 8 nhóm kiểm tra: đủ 2 vùng, S3 không công khai, không mở 22/3389 ra Internet, ALB chỉ 443, EC2 chỉ nhận từ ALB, RDS không công khai và có mã hóa, IAM không dùng `*`, EC2 bật IMDSv2 và mã hóa ổ đĩa, ALB chỉ HTTPS, từ chối image dùng tag |
| `ec2 bootstrap (Ubuntu 24.04)` | Chạy đúng `ec2_bootstrap.sh` trên máy Ubuntu 24.04 của GitHub (cùng hệ điều hành với AMI của EC2), với image đã ký mới nhất của `main`; sau đó thử base image chưa ký | Script khởi động chạy được: kiểm chữ ký đạt, container chạy với thiết lập bảo mật, `/health` trả lời; image không có chữ ký của repo bị từ chối |

Phần **chưa** chứng minh được khi không có tài khoản: AWS thực sự tạo được tài nguyên (giới hạn tài khoản, hạn mức, AMI theo vùng), ALB định tuyến được tới EC2, chứng chỉ ACM và DNS.

### Triển khai thật khi có tài khoản AWS

1. Có tên miền và chứng chỉ ACM cho tên miền đó tại `ap-southeast-1`.
2. Đặt AWS Budgets 1-5 USD kèm cảnh báo email.
3. Lấy digest image đã ký: mở run push `main` mới nhất, job **release**, dòng `Pushed ghcr.io/...@sha256:...`.
4. Chạy trong `Code/DevSecOps/infra`:

```bash
export TF_VAR_db_password="$(openssl rand -hex 16)"
terraform init
terraform plan -out tfplan \
  -var 'app_image=ghcr.io/tranhuultai/devsecops@sha256:<digest>' \
  -var 'certificate_arn=arn:aws:acm:ap-southeast-1:<account>:certificate/<id>'
terraform apply tfplan
terraform output alb_dns_name
```

5. Tạo bản ghi DNS (CNAME) từ tên miền trỏ về `alb_dns_name`, đợi target group báo healthy, gọi `https://<tên miền>/health`.
6. Kiểm cấu hình bằng AWS CLI, ví dụ `aws s3api get-public-access-block --bucket <bucket>`, `aws rds describe-db-instances --query 'DBInstances[].PubliclyAccessible'`.
7. Xong thì `terraform destroy` và kiểm lại trên console.

## 5. Tái lập kiểm thử và thực nghiệm

```bash
# Môi trường và kiểm thử
python -m pip install -r requirements.txt
python -m pytest -q Code/DevSecOps/src/test Code/DevSecOps/tests
for g in g0 g1 g2; do conftest verify -p Code/DevSecOps/policy/$g; done
conftest verify -p Code/DevSecOps/rules/conftest
for p in Code/DevSecOps/ground_truth/patches/*.patch; do git apply --check "$p"; done

# Thực nghiệm E1, E2, E4 (bộ đáp án đóng băng ở tag gt-v1)
gh workflow run experiments.yml -f gt_ref=gt-v1
# Thực nghiệm E3 (thời gian, 6 lượt mỗi cấu hình)
gh workflow run e3-orchestrate.yml -f reps=6

# Tải dữ liệu thô rồi sinh lại bảng, biểu đồ và so_lieu_bao_cao.csv
gh run download <run_id> -D Code/DevSecOps/tests/results/raw/<thu_muc_moi>
python Code/DevSecOps/tests/analyze_results.py      # hoặc mở analysis.ipynb
```

Số liệu trong báo cáo lấy từ run `41659076551` (E1, E2, E4) và `41698953799` (E3); dữ liệu thô đã lưu trong `Code/DevSecOps/tests/results/raw/`. Cơ sở dữ liệu lỗ hổng thay đổi theo ngày, nên chạy lại có thể ra số CVE khác; tỷ lệ phát hiện lỗi gieo cài không phụ thuộc yếu tố này, trừ các mẫu dependency và base image (D09-D12).

## 6. Dọn tài nguyên

| Tài nguyên | Cách dọn |
| --- | --- |
| Cụm `kind` | Tự mất khi job kết thúc. Thử tại máy: `kind delete cluster --name smoke` |
| Image trên GHCR | Mỗi lần push `main` tạo một phiên bản. Xóa bản cũ ở trang **Packages** của tài khoản, hoặc `gh api -X DELETE /user/packages/container/devsecops/versions/<id>` |
| Artifact của Actions | Tự hết hạn: báo cáo của job `security-scan` 14 ngày, E3 từng lượt 7 ngày, dữ liệu thực nghiệm 90 ngày, các artifact khác theo mặc định của repo. Xóa sớm ở trang Actions hoặc `gh api -X DELETE /repos/<owner>/<repo>/actions/artifacts/<id>` |
| Nhánh thí nghiệm, demo | Xóa sau khi merge hoặc sau buổi báo cáo |
| AWS | Không có, vì không `apply`. Nếu triển khai thật: đặt AWS Budgets kèm cảnh báo trước `terraform apply`; dùng xong chạy `terraform destroy` và kiểm lại trên console (EC2, ALB, RDS, địa chỉ IP công khai, ổ đĩa EBS) |

## 7. Chi phí

Chi phí thực tế của đề tài là 0 đồng: runner GitHub-hosted miễn phí cho repo công khai, Terraform không `apply`, cụm `kind` chạy trong runner.

Ước tính nếu chạy trên repo riêng, dùng thời gian job đo từ GitHub API và đơn giá runner Linux 2 nhân 0,006 USD/phút (GitHub, 2026):

| Kịch bản | Phút runner | Chi phí (USD) |
| --- | --- | --- |
| Một lần chạy pull request (run 41699668185) | 4,72 | 0,028 |
| Một lần push `main` có release và deploy-smoke (run 41700761072) | 7,12 | 0,043 |
| Một tháng: 100 PR và 30 lần push `main` | 685,6 | 4,11 |
| Tải gấp 2 (200 PR, 60 push) | 1.371,2 | 8,23 |
| Tải gấp 5 (500 PR, 150 push) | 3.428,0 | 20,57 |
| Một đợt thực nghiệm E1, E2, E4 (49 job) | 82,13 | 0,49 |
| Một đợt thực nghiệm E3 (18 lượt) | 55,22 | 0,33 |

Gói GitHub Free có 12 USD mức sử dụng tính toán mỗi tháng cho repo riêng, đủ cho kịch bản 100 PR/tháng.

Ước tính nếu triển khai thật hạ tầng Terraform tại Singapore (chưa kiểm bằng AWS Pricing Calculator):

| Thành phần | Đơn giá tham khảo | Nguồn |
| --- | --- | --- |
| EC2 `t3.micro` | 0,0132 USD/giờ | DoiT, bảng giá `ap-southeast-1` |
| ALB | 0,0225 USD/giờ + 0,008 USD/LCU-giờ | AWS, giá ví dụ ở `us-east-1`; Singapore có thể cao hơn |
| Địa chỉ IPv4 công khai (EC2 1 địa chỉ, ALB 2 vùng) | 0,005 USD/giờ mỗi địa chỉ | AWS, áp dụng từ 01/02/2024 |
| RDS `db.t3.micro` | khoảng 20 USD/tháng, tức khoảng 0,028 USD/giờ | Bytebase, nguồn thứ cấp |

Cộng lại khoảng 0,09 USD/giờ, tức dưới 0,2 USD cho một buổi thử 2 giờ rồi `destroy`, và khoảng 60-70 USD nếu chạy cả tháng (chưa gồm ổ đĩa, sao lưu, dữ liệu truyền ra). Tài khoản AWS mới chọn gói Free có 100-200 USD credit trong 6 tháng, đủ cho buổi thử.

## 8. Rủi ro còn lại

| Rủi ro | Nguyên nhân | Mức | Hướng xử lý |
| --- | --- | --- | --- |
| PR bị gate chặn vẫn có thể merge | Ruleset chưa đặt `gate` là required status check; chủ repo được bỏ qua ruleset | Cao | Làm đủ bước 3 ở mục 3 |
| Bỏ sót lỗi mã chưa có luật | Luật Semgrep tự viết bám lỗi đã biết; `p/python` chỉ bắt 1/6 | Trung bình | Thêm bộ luật có phiên bản, đo lại |
| Quyết định đổi theo ngày | Dữ liệu lỗ hổng, KEV, EPSS cập nhật liên tục | Trung bình | Quét lại định kỳ, lưu ảnh chụp dữ liệu |
| CVE chưa có bản vá | 9 CVE HIGH còn trong image, chỉ cảnh báo | Trung bình | Theo dõi bản vá, cân nhắc base distroless |
| Lỗi tồn đọng trên baseline | 96 cảnh báo ở chế độ full | Thấp | Giảm dần theo kế hoạch, ngoại lệ có hạn |
| Rule ID lệch giữa hai công cụ | Cùng lỗi, Checkov chặn, Trivy cảnh báo | Thấp | Ánh xạ theo loại lỗi |
| Phụ thuộc bên thứ ba | Scanner, action, Sigstore ngoài quyền kiểm soát | Thấp | Ghim SHA, kiểm checksum |
| Không có kiểm soát lúc chạy | Chỉ kiểm tra tĩnh, thử trên `kind` | Ngoài phạm vi | Admission control, giám sát runtime |
| Chưa `apply` thật lên AWS | Nhóm không có tài khoản AWS | Trung bình | Đã kiểm bằng validate, test giả lập và chạy thử script EC2 (mục 4a); khi có tài khoản làm theo các bước ở mục 4a |
| EC2 có địa chỉ IP công khai | Để tải image mà không cần NAT Gateway | Thấp | Security group không mở cổng nào ra Internet; muốn bỏ IP công khai thì thêm NAT Gateway hoặc VPC endpoint |
