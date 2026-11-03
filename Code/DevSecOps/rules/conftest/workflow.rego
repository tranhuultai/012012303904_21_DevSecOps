# Luật phát hiện lỗi workflow (D26-D28) cho Conftest; là đầu vào máy quét, không phải luật gate.
# Mã GHA-... riêng để không trùng rule ID của Checkov khi gộp finding.
package main

import rego.v1

# D26: token workflow cấp quyền write-all.
deny contains msg if {
	input.permissions == "write-all"
	msg := "GHA-WRITE-ALL: workflow-level permissions write-all"
}

deny contains msg if {
	some name, job in input.jobs
	object.get(job, "permissions", "") == "write-all"
	msg := sprintf("GHA-WRITE-ALL: job %v permissions write-all", [name])
}

# D27: script injection - chèn biểu thức github.event thẳng vào lệnh run.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.run)
	contains(step.run, "${{ github.event")
	msg := sprintf("GHA-SCRIPT-INJECTION: github.event expression in run of job %v", [name])
}

# D28: action tham chiếu mutable (tag/nhánh), không ghim SHA 40 ký tự.
deny contains msg if {
	some name, job in input.jobs
	some step in object.get(job, "steps", [])
	is_string(step.uses)
	not regex.match("^[^@]+@[0-9a-f]{40}$", step.uses)
	msg := sprintf("GHA-UNPINNED-ACTION: mutable action reference %v in job %v", [step.uses, name])
}
