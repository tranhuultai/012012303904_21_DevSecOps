# E3 – Thời gian CI theo cache profile

**Trạng thái bằng chứng:** `complete`

| Cache pip | N hợp lệ | Lượt G2 chặn baseline | Wall median (s) | Wall IQR (s) | Wall p90 (s) | Scan stage median (s) | Scan runner-minutes median |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold | 5 | 5 | 104.0 | 4.0 | 110.4 | 88.0 | 2.65 |
| warm | 5 | 5 | 110.0 | 6.0 | 116.6 | 90.0 | 2.78 |

## Thời gian từng job

| Cache | Job | N | Median (s) | IQR (s) | p90 (s) |
|---|---|---:|---:|---:|---:|
| cold | Prepare Trivy and Grype vulnerability DB snapshots | 5 | 29.0 | 3.0 | 31.2 |
| cold | Run Python tests | 5 | 18.0 | 4.0 | 20.8 |
| cold | Security scans (collection mode) | 5 | 34.0 | 3.0 | 36.2 |
| cold | deploy-smoke | 5 | 0.0 | 0.0 | 0.0 |
| cold | gate (Conftest Rego) | 5 | 14.0 | 1.0 | 15.6 |
| cold | iac | 5 | 42.0 | 4.0 | 44.0 |
| cold | image | 5 | 56.0 | 3.0 | 60.2 |
| cold | release | 5 | 0.0 | 0.0 | 0.0 |
| warm | Prepare Trivy and Grype vulnerability DB snapshots | 5 | 30.0 | 9.0 | 34.4 |
| warm | Run Python tests | 5 | 19.0 | 5.0 | 20.0 |
| warm | Security scans (collection mode) | 5 | 34.0 | 3.0 | 37.0 |
| warm | deploy-smoke | 5 | 0.0 | 0.0 | 0.0 |
| warm | gate (Conftest Rego) | 5 | 13.0 | 4.0 | 17.6 |
| warm | iac | 5 | 35.0 | 9.0 | 44.2 |
| warm | image | 5 | 63.0 | 1.0 | 66.6 |
| warm | release | 5 | 0.0 | 0.0 | 0.0 |

## So sánh cache

- Warm có median wall **6.0 giây chậm hơn** cold (+5.77%). profile pip cache warm có wall median chậm hơn profile cold.

## Điều kiện và giới hạn

- Cache comparison covers pip package downloads for the test job, Semgrep, and Checkov. Separate versioned immutable Trivy and Grype vulnerability DB caches are shared by both profiles and excluded from the pip-cache variable.
- GitHub-hosted runner hardware and external network conditions can vary between runs; report the observed spread.
- Wall time is the measured workflow job interval for the dispatch run; release and kind deploy-smoke are skipped on workflow_dispatch.
- A run with a blocked baseline gate is retained only when tests, DB preparation, and all scanner jobs succeeded and the gate is the sole failed job; other workflow failures are excluded.
- A complete cache comparison requires one shared Trivy and Grype vulnerability DB snapshot across both profiles; the workflow records both snapshot keys and runtime DB metadata.

Số run bị loại: **1**.
