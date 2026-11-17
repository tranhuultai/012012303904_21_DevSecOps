# E1/E2 – Kết quả từ quan sát CI theo fixture

- Trạng thái dữ liệu: **partial**
- Commit baseline: `f7fc110487f2e81a1729e8317ba0457b414a0bb2`
- Fixture D/C đã đo: 3/38
- Negative controls đã đo: 0/8

## E1 – Finding mới từ scanner kỳ vọng

- Finding mới đúng tool/rule/file: 1/3 lần chạy lỗi gieo cài.
- C changes có finding mới: chưa có dữ liệu lần chạy clean.

## E2 – Quyết định gate theo policy

| Policy | TP | FN | FP | TN | Recall chặn lỗi | False-block trên clean |
|---|---:|---:|---:|---:|---:|---:|
| G0 | 0 | 3 | 0 | 0 | 0.00% | chưa đủ dữ liệu |
| G1 | 1 | 2 | 0 | 0 | 33.33% | chưa đủ dữ liệu |
| G2 | 1 | 2 | 0 | 0 | 33.33% | chưa đủ dữ liệu |

## N – Negative controls

- Finding mới đúng rule/CVE đích từ scanner kỳ vọng: chưa có dữ liệu lần chạy control.
- Tỷ lệ trên là false positive của scanner trên N controls; nó không gộp với false-block của gate trên C changes.

| Policy | Control bị BLOCK | Control không BLOCK | False-block trên N |
|---|---:|---:|---:|
| G0 | 0 | 0 | chưa đủ dữ liệu |
| G1 | 0 | 0 | chưa đủ dữ liệu |
| G2 | 0 | 0 | chưa đủ dữ liệu |

## Giới hạn và mẫu còn thiếu

- Các mẫu N chưa có kết quả thì không được suy ra là true negative.
- Chỉ gộp các run có cùng commit baseline và cùng phiên bản công cụ.
- Xem JSON cạnh file này để truy vết run URL, finding, policy, report hash và fixture.

Thiếu fixture: C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11, D12, D13, D14, D15, D16, D17, D18, D19, D20, D21, D22, D23, D24, D25.
Thiếu negative control: N01, N02, N03, N04, N05, N06, N07, N08.
