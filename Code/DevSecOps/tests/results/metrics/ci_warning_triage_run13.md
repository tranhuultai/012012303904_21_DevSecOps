# Triage 15 cảnh báo MEDIUM – GitHub Actions run #13

Nguồn: [run #13, attempt 1](https://github.com/gialong611/DevSecOps_Project/actions/runs/41288998886/attempts/1), commit `cbcef8e32d5b007229be5e424409e8ee00fe278e`. Các ID và phiên bản cài đặt lấy từ artifact `report-gate`/`report-scan`; các phiên bản đích bên dưới là remediation local và chưa được CI xác nhận.

| Package | Cảnh báo | Phiên bản trong artifact | Thay đổi local | ID advisory | Trạng thái |
|---|---:|---|---|---|---|
| Python base image | 5 | 3.12.16 | `python:3.13.18` | CVE-2025-12781, CVE-2025-15366, CVE-2025-15367, CVE-2026-3446, CVE-2026-6019 | Đã đổi base image và setup-python; chờ scan mới |
| pip | 5 | 25.0.1 | 26.2.2 | GHSA-4XH5-X5GV-QWPH, GHSA-58QW-9MGM-455V, GHSA-JP4C-XJXW-MGF9, GHSA-QWM4-QH6W-59XR, GHSA-WF93-45JW-7689 | Đã ghim pip trong CI và Dockerfile; chờ scan mới |
| pytest | 2 | 8.3.4 | 9.0.3 | CVE-2025-71176, GHSA-6W46-J5RX-G56G | Đã đổi requirements và fixture patches; chờ kiểm tra tương thích/scan |
| Starlette | 3 | 0.41.3 | Chưa đổi | GHSA-2C2J-9GV5-CJ73, GHSA-86QP-5C8J-P5MR, GHSA-X746-7M8F-X49C | Hoãn migration major; review tương thích trước |

## Quyết định gate

- Run #13 có 15 HIGH và 15 MEDIUM warning, 0 blocker. Gate là `WARN`.
- Local changes nhắm tới 12/15 cảnh báo MEDIUM; 3 Starlette được hoãn. Nếu scan mới xác nhận cả 12 advisory đã hết và không xuất hiện finding mới, dự kiến còn 18 warning (15 HIGH + 3 MEDIUM). Đây là dự báo, không phải số đo.
- Không nâng 15 HIGH thành BLOCK: artifact ghi chúng chưa có bản vá; gate hiện cảnh báo để tránh chặn không có remediation khả thi.
- Chỉ chốt kết quả sau CI: xác nhận phiên bản package/image thực tế, chạy unit tests/compatibility, kiểm tra finding ID và warning count, sau đó cập nhật `ci_baseline_latest.json`.

## Căn cứ phiên bản

- Python 3.13.18 là bản security release: [Python.org release page](https://www.python.org/downloads/release/python-31318/).
- Image chính thức được ghim digest: [Docker Official Image – Python 3.13.18 slim-trixie](https://hub.docker.com/layers/library/python/3.13.18-slim-trixie/images/sha256-aaf08c5490d52cd92bc27142a5215b1e47355a5eaf9adfad2a0fbc022d0b5490).
- pip 26.2.2: [PyPI release metadata](https://pypi.org/pypi/pip/26.2.2/json).
- pytest 9.0.3: [PyPI release metadata](https://pypi.org/pypi/pytest/9.0.3/json).
- FastAPI 0.115.6 currently pins Starlette below 0.42.0; Starlette 1.1.0 is marked Alpha on PyPI. Vì vậy chưa áp dụng bản sửa yêu cầu chuyển sang nhánh Starlette 1.x: [FastAPI metadata](https://pypi.org/pypi/fastapi/0.115.6/json), [Starlette 1.1.0 metadata](https://pypi.org/pypi/starlette/1.1.0/json).
