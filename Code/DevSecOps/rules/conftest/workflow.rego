# Luật kiểm tra GitHub Actions bằng Conftest:
#   conftest test -p rules/conftest ../../.github/workflows/ci.yml
# D26-D28 là rule riêng của đề tài; Checkov hiện không phân tích được workflow
# trong CI này nên không được dùng làm nguồn bằng chứng cho ba fixture đó.
package main

import rego.v1

# D26 / DSEC_GHA_002: workflow hoặc job cấp token write-all.
deny contains msg if {
	input.permissions == "write-all"
	msg := "DSEC_GHA_002: workflow-level permissions write-all"
}

deny contains msg if {
	some name, job in input.jobs
	object.get(job, "permissions", "") == "write-all"
	msg := sprintf("DSEC_GHA_002: job-level permissions write-all in %v", [name])
}

# D27 / DSEC_GHA_003: dữ liệu từ GitHub event được nội suy trực tiếp vào run:.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.run)
	contains(step.run, "${{ github.event")
	msg := sprintf("DSEC_GHA_003: untrusted github.event interpolation in job %v", [name])
}

# D28 / DSEC_GHA_001: action tham chiếu mutable (tag/nhánh), không ghim SHA 40 ký tự.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.uses)
	not regex.match("^[^@]+@[0-9a-f]{40}$", step.uses)
	msg := sprintf("DSEC_GHA_001: mutable action reference %v in job %v", [step.uses, name])
}
