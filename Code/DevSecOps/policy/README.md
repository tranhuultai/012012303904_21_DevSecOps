# Chính sách Security Gate (Policy as Code)

Thư mục này chứa các chính sách kiểm soát an ninh (Security Gates) viết bằng Rego (Open Policy Agent v1.0), được thực thi bởi Conftest trong pipeline CI/CD.

## Người phụ trách: Hoàng Gia Long (Long - gialong611)

---

## 1. Kiến trúc ba tầng chính sách (G0, G1, G2)

| Chính sách | Mục đích | Tiêu chí chặn (BLOCK) | Tiêu chí cảnh báo (WARN) |
|---|---|---|---|
| **G0** | Đo nhiễu nền (Baseline) | Không bao giờ chặn (`false`) | Không |
| **G1** | Mặc định (Naive / Strict) | Mọi finding có mức `CRITICAL`, `HIGH`, `MEDIUM` | `LOW`, `INFO` |
| **G2** | Ngữ cảnh thông minh (Context-aware) | • `secret` (không cho phép ngoại lệ)<br>• CVE thuộc danh mục KEV (mọi mức)<br>• CVE có EPSS cao (≥ 0.10, tức xác suất khai thác ≥ 10%)<br>• SCA/Image `CRITICAL`/`HIGH` có bản vá và độ tin cậy cao<br>• Cấu hình IaC/K8s/CI thuộc danh mục kiểm soát nguy cơ cao<br>• SAST `CRITICAL`/`HIGH`<br>• Ngoại lệ hết hạn hoặc tự duyệt | • `HIGH` chưa có bản vá<br>• `MEDIUM` có bản vá<br>• CVE có EPSS trung bình (0.01 ≤ EPSS < 0.10)<br>• Ngoại lệ sắp hết hạn (≤ 7 ngày) |

---

## 2. Nguyên tắc cốt lõi

### 2.1. Fail-closed
Nếu dữ liệu đầu vào thiếu hoặc sai định dạng bắt buộc, Gate sẽ lập tức chặn (BLOCK):
- Thiếu `input.context.today` (ngày đánh giá)
- Thiếu `input.findings` (mảng phát hiện từ các công cụ quét)
- Finding thiếu trường `severity`

### 2.2. Kiểm soát ngoại lệ (Exception Policy)
Ngoại lệ hợp lệ phải thỏa mãn:
1. Có đầy đủ `owner`, `approved_by`, `reason`, `match.rule_id`, `match.resource`.
2. `owner != approved_by` (nghiêm cấm tự duyệt ngoại lệ).
3. Ngày hết hạn (`expires`) phải sau ngày hiện tại (`today`).
4. Thời hạn không vượt trần quy định theo mức độ:
   - `CRITICAL`: tối đa 7 ngày
   - `HIGH`: tối đa 30 ngày
   - `MEDIUM` / `LOW`: tối đa 90 ngày
5. Bí mật (Secret) **không được phép** tạo ngoại lệ.

---

## 3. Cấu trúc thư mục

```text
policy/
├── g0/
│   ├── gate.rego          # Chính sách G0
│   └── gate_test.rego     # Unit tests cho G0
├── g1/
│   ├── gate.rego          # Chính sách G1 (fail-closed, severity-based)
│   └── gate_test.rego     # Unit tests cho G1
├── g2/
│   ├── gate.rego          # Chính sách G2 (KEV, fixable, control-keys, exceptions)
│   └── gate_test.rego     # Unit tests cho G2
└── README.md
```

---

## 4. Kiểm thử chính sách

Chạy toàn bộ unit test với `conftest verify`:

```powershell
# Bằng PowerShell script:
.\Code\DevSecOps\tests\run_policy_tests.ps1

# Hoặc lệnh conftest trực tiếp:
conftest verify -p Code/DevSecOps/policy/g0
conftest verify -p Code/DevSecOps/policy/g1
conftest verify -p Code/DevSecOps/policy/g2
```

