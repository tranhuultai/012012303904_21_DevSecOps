# E1/E2 – Kết quả từ quan sát CI theo fixture

- Trạng thái dữ liệu: **complete**
- Commit baseline theo cặp: `135606475be9d66842121135631d853a63c1e480`
- Fixture D/C đã đo: 38/38
- Negative controls đã đo: 8/8

## E1 – Finding mới từ scanner kỳ vọng

- Finding mới đúng tool/rule/file: 28/28 lần chạy lỗi gieo cài.
- C changes có finding mới: 0/10 lần chạy clean.

## E2 – Quyết định gate theo policy

TP/FN/FP/TN xét gate có thêm blocker so với baseline hay không; `Block trúng rule đích` yêu cầu blocker khớp CVE/rule gieo cài. Nếu hai số khác nhau, gate đã chặn nhưng do blocker khác.

| Policy | TP | FN | FP | TN | Block recall | Block trúng rule đích | Đúng hành động | False-block clean |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| G0 | 0 | 0 | 0 | 38 | không áp dụng (G0 không có mẫu kỳ vọng BLOCK) | — | 100.00% | 0.00% |
| G1 | 28 | 0 | 0 | 10 | 100.00% | 27/28 | 100.00% | 0.00% |
| G2 | 23 | 0 | 0 | 15 | 100.00% | 22/23 | 100.00% | 0.00% |

## N – Negative controls

- Finding mới đúng rule/CVE đích từ scanner kỳ vọng: 0/8 lần chạy control.
- Tỷ lệ trên là false positive của scanner trên N controls; nó không gộp với false-block của gate trên C changes.

| Policy | Control bị BLOCK | Control không BLOCK | False-block trên N |
|---|---:|---:|---:|
| G0 | 0 | 8 | 0.00% |
| G1 | 1 | 7 | 12.50% |
| G2 | 0 | 8 | 0.00% |

## Giới hạn và mẫu còn thiếu

- Các mẫu N chưa có kết quả thì không được suy ra là true negative.
- Mỗi fixture chỉ được so với baseline cùng commit; nếu có nhiều commit thì mỗi commit cần baseline riêng và cùng phiên bản công cụ.
- Xem JSON cạnh file này để truy vết run URL, finding, policy, report hash và fixture.

Thiếu fixture: không.
Thiếu negative control: không.
