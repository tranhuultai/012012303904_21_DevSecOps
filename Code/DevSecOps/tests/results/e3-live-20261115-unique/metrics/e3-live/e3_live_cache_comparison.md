# E3 – Thời gian CI theo cache profile

**Trạng thái bằng chứng:** `complete`

| Cache pip | N hợp lệ | Wall median (s) | Wall IQR (s) | Wall p90 (s) | Scan stage median (s) | Scan runner-minutes median |
|---|---:|---:|---:|---:|---:|---:|
| cold | 5 | 138.0 | 5.0 | 153.2 | 122.0 | 3.33 |
| warm | 5 | 150.0 | 9.0 | 154.4 | 128.0 | 3.28 |

## Thời gian từng job

| Cache | Job | N | Median (s) | IQR (s) | p90 (s) |
|---|---|---:|---:|---:|---:|
| cold | Run Python tests | 5 | 17.0 | 6.0 | 21.6 |
| cold | Security scans (collection mode) | 5 | 38.0 | 6.0 | 40.0 |
| cold | deploy-smoke | 5 | 0.0 | 0.0 | 0.0 |
| cold | gate (Conftest Rego) | 5 | 14.0 | 0.0 | 16.4 |
| cold | iac | 5 | 44.0 | 5.0 | 46.2 |
| cold | image | 5 | 122.0 | 7.0 | 136.8 |
| cold | release | 5 | 0.0 | 0.0 | 0.0 |
| warm | Run Python tests | 5 | 14.0 | 2.0 | 15.6 |
| warm | Security scans (collection mode) | 5 | 31.0 | 4.0 | 33.2 |
| warm | deploy-smoke | 5 | 0.0 | 0.0 | 0.0 |
| warm | gate (Conftest Rego) | 5 | 18.0 | 5.0 | 20.8 |
| warm | iac | 5 | 42.0 | 7.0 | 47.8 |
| warm | image | 5 | 128.0 | 4.0 | 133.0 |
| warm | release | 5 | 0.0 | 0.0 | 0.0 |

## So sánh cache

- Chênh lệch median wall warm − cold: **12.0 giây** (8.7%). negative means the warm pip-cache profile was faster by the median wall time.

## Điều kiện và giới hạn

- Cache comparison covers pip package downloads for the test job, Semgrep, and Checkov; scanner binaries and Trivy vulnerability databases are not cached by this variable.
- GitHub-hosted runner hardware and external network conditions can vary between runs; report the observed spread.
- Wall time is the measured workflow job interval for the dispatch run; release and kind deploy-smoke are skipped on workflow_dispatch.
- A complete cache comparison requires one shared Trivy vulnerability DB snapshot across both profiles; repeat the study if the DB changes during collection.

Số run bị loại: **1**.
