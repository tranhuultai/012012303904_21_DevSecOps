# Luật PHÁT HIỆN lỗi workflow GitHub Actions (D26-D28), chạy bằng Conftest:
#   conftest test -p rules/conftest lab/workflows-vuln/ci-vuln.yml
# Khác policy/: đây là luật đầu vào của máy quét, không phải luật chặn của gate.
package main

import rego.v1

# D26 / CKV2_GHA_1: token workflow cấp quyền write-all.
deny contains msg if {
	input.permissions == "write-all"
	msg := "CKV2_GHA_1: workflow-level permissions write-all"
}

deny contains msg if {
	some name, job in input.jobs
	object.get(job, "permissions", "") == "write-all"
	msg := sprintf("CKV2_GHA_1: job %v permissions write-all", [name])
}

# D27 / CKV_GHA_2: script injection - chèn biểu thức github.event vào run.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.run)
	contains(step.run, "${{ github.event")
	msg := sprintf("CKV_GHA_2: script injection via github.event in job %v", [name])
}

# D28 / CKV_GHA_7: action tham chiếu mutable (tag/nhánh), không ghim SHA 40 ký tự.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.uses)
	not regex.match("^[^@]+@[0-9a-f]{40}$", step.uses)
	msg := sprintf("CKV_GHA_7: mutable action reference %v in job %v", [step.uses, name])
}
