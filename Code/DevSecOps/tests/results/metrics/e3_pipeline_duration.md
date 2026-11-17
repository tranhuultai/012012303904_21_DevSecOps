# E3 – Thời gian CI theo cache profile

**Trạng thái bằng chứng:** `complete`

| Cache pip | N hợp lệ | Lượt G2 chặn baseline | Wall median (s) | Wall IQR (s) | Wall p90 (s) | Tổng runner-minutes median | Scan stage median (s) | Scan runner-minutes median |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cold | 5 | 0 | 111.0 | 3.0 | 115.8 | 3.45 | 87.0 | 2.85 |
| warm | 5 | 0 | 125.0 | 10.0 | 126.6 | 3.63 | 97.0 | 3.02 |

## Thời gian từng job

| Cache | Job | N đo được | Median (s) | IQR (s) | p90 (s) |
|---|---|---:|---:|---:|---:|
| cold | Prepare Trivy and Grype vulnerability DB snapshots | 5 | 33.0 | 6.0 | 33.0 |
| cold | Run Python tests | 5 | 14.0 | 3.0 | 17.6 |
| cold | Security scans (collection mode) | 5 | 36.0 | 1.0 | 37.2 |
| cold | deploy-smoke (skipped) | — | — | — | — |
| cold | gate (Conftest Rego) | 5 | 21.0 | 4.0 | 24.4 |
| cold | iac | 5 | 48.0 | 7.0 | 51.2 |
| cold | image | 5 | 56.0 | 2.0 | 58.4 |
| cold | release (skipped) | — | — | — | — |
| warm | Prepare Trivy and Grype vulnerability DB snapshots | 5 | 30.0 | 4.0 | 33.2 |
| warm | Run Python tests | 5 | 19.0 | 2.0 | 20.0 |
| warm | Security scans (collection mode) | 5 | 33.0 | 2.0 | 34.6 |
| warm | deploy-smoke (skipped) | — | — | — | — |
| warm | gate (Conftest Rego) | 5 | 17.0 | 1.0 | 22.8 |
| warm | iac | 5 | 41.0 | 13.0 | 53.8 |
| warm | image | 5 | 67.0 | 5.0 | 72.4 |
| warm | release (skipped) | — | — | — | — |

## So sánh cache

- Warm có median wall **14.0 giây chậm hơn** cold (+12.61%). profile pip cache warm có wall median chậm hơn profile cold.

## Điều kiện và giới hạn

- Cache comparison covers pip package downloads for the test job, Semgrep, and Checkov. Separate versioned immutable Trivy and Grype vulnerability DB caches are shared by both profiles and excluded from the pip-cache variable.
- GitHub-hosted runner hardware and external network conditions can vary between runs; report the observed spread.
- Wall time is the measured workflow job interval for the dispatch run; release and kind deploy-smoke are skipped on workflow_dispatch.
- A run with a blocked baseline gate is retained only when tests, DB preparation, and all scanner jobs succeeded and the gate is the sole failed job; other workflow failures are excluded.
- A complete cache comparison requires one shared Trivy and Grype vulnerability DB snapshot across both profiles; the workflow records both snapshot keys and runtime DB metadata.

Số run bị loại: **1**.
