# E2 – So sánh chính sách G0 / G1 / G2

> **RQ3**: Chính sách nào chặn đủ lỗi nghiêm trọng mà ít chặn nhầm mã sạch nhất?

## Bảng so sánh

| Policy | Recall | Precision | F1 | False-block | TP | FN | FP |
|--------|--------|-----------|-----|-------------|-----|-----|-----|
| G0 | 0.00% | 0.00% | 0.0000 | 0.00% | 0 | 28 | 0 |
| G1 | 100.00% | 100.00% | 1.0000 | 0.00% | 28 | 0 | 0 |
| G2 | 78.57% | 100.00% | 0.8800 | 0.00% | 22 | 6 | 0 |

## Kết luận

Chính sách được khuyến nghị: **G1**

_Chặn tất cả MEDIUM+ (không xét bản vá, KEV, ngoại lệ)_

## Lỗi bỏ sót theo chính sách

- **G0**: 28 lỗi bỏ sót (D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11, D12, D13, D14, D15, D16, D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28)
- **G1**: 0 lỗi bỏ sót
- **G2**: 6 lỗi bỏ sót (D04, D06, D20, D22, D23, D28)
