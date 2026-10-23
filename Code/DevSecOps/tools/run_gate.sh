#!/usr/bin/env bash
# Kiểm gate_input.json bằng JSON Schema (fail-closed) rồi chạy Conftest với đúng một
# thư mục chính sách. Ghi gate-result.json, trả đúng mã thoát của Conftest.
# Dùng: run_gate.sh <policy_dir> <gate_input.json> [gate-result.json]
set -euo pipefail

policy_dir="$1"
gate_input="$2"
result="${3:-gate-result.json}"
here="$(cd "$(dirname "$0")" && pwd)"

python "${here}/validate_schema.py" "${here}/../schemas/gate_input.schema.json" "${gate_input}"

set +e
conftest test -p "${policy_dir}" "${gate_input}" --output json > "${result}"
code=$?
set -e

conftest test -p "${policy_dir}" "${gate_input}" || true
exit "${code}"
