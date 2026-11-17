# E1/E2 – Kết quả từ quan sát CI theo fixture

- Trạng thái dữ liệu: **partial**
- Commit baseline: `b79a12a6a3e8c291ac4f2050db6946d841f2116a`
- Fixture D/C đã đo: 38/38
- Negative controls đã đo: 8/8

## E1 – Finding mới từ scanner kỳ vọng

- Finding mới đúng tool/rule/file: 11/28 lần chạy lỗi gieo cài.
- C changes có finding mới: 1/10 lần chạy clean.

## E2 – Quyết định gate theo policy

| Policy | TP | FN | FP | TN | Recall chặn lỗi | False-block trên clean |
|---|---:|---:|---:|---:|---:|---:|
| G0 | 0 | 28 | 0 | 10 | 0.00% | 0.00% |
| G1 | 15 | 13 | 0 | 10 | 53.57% | 0.00% |
| G2 | 10 | 18 | 0 | 10 | 35.71% | 0.00% |

## N – Negative controls

- Finding mới đúng rule/CVE đích từ scanner kỳ vọng: 0/8 lần chạy control.
- Tỷ lệ trên là false positive của scanner trên N controls; nó không gộp với false-block của gate trên C changes.

| Policy | Control bị BLOCK | Control không BLOCK | False-block trên N |
|---|---:|---:|---:|
| G0 | 0 | 8 | 0.00% |
| G1 | 2 | 6 | 25.00% |
| G2 | 1 | 7 | 12.50% |

## Giới hạn và mẫu còn thiếu

- Các mẫu N chưa có kết quả thì không được suy ra là true negative.
- Chỉ gộp các run có cùng commit baseline và cùng phiên bản công cụ.
- Xem JSON cạnh file này để truy vết run URL, finding, policy, report hash và fixture.

Thiếu fixture: không.
Thiếu negative control: không.
