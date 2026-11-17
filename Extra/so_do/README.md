# Sơ đồ trong báo cáo

Mỗi sơ đồ có tệp nguồn (sửa được) và ảnh PNG đã dùng trong báo cáo, slide.

| Tệp | Hình trong báo cáo | Loại |
| --- | --- | --- |
| `hinh_2_1_kien_truc_hien_trang` | Hình 2.1. Kiến trúc hiện trạng | Kiến trúc (Graphviz) |
| `hinh_2_2_kien_truc_muc_tieu` | Hình 2.2. Kiến trúc mục tiêu của đường ống DevSecOps | Kiến trúc (Graphviz) |
| `hinh_2_3_luong_du_lieu` | Hình 2.3. Luồng dữ liệu findings đến quyết định gate | Luồng dữ liệu (Graphviz) |
| `hinh_2_4_trinh_tu_pull_request` | Hình 2.4. Trình tự xử lý pull request qua security gate | Trình tự (Mermaid) |
| `hinh_2_5_quy_trinh_thuc_nghiem` | Hình 2.5. Quy trình thu thập và phân tích dữ liệu thực nghiệm | Quy trình (Graphviz) |

Biểu đồ kết quả E1-E4 (Hình 2.6-2.9) sinh từ dữ liệu bằng `Code/DevSecOps/tests/analyze_results.py`, nằm ở `Code/DevSecOps/tests/results/figures/`; bản trong báo cáo chỉ đổi cách ghi số sang dấu phẩy thập phân.

Vẽ lại ảnh sau khi sửa nguồn:

```bash
for f in *.dot; do dot -Tpng -Gdpi=220 "$f" -o "${f%.dot}.png"; done
mmdc -i hinh_2_4_trinh_tu_pull_request.mmd -o hinh_2_4_trinh_tu_pull_request.png -c mermaid_config.json -s 3 -b white
```
