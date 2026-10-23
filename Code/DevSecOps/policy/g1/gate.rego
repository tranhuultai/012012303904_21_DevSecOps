package main

import rego.v1

# G1: chặn mọi phát hiện từ MEDIUM trở lên, không xét KEV, bản vá hay ngoại lệ.
blocking_severity := {"CRITICAL", "HIGH", "MEDIUM"}

# Fail-closed: thiếu dữ liệu bắt buộc thì chặn.
deny contains msg if {
	not input.context.today
	msg := "fail-closed: thiếu context.today"
}

deny contains msg if {
	not input.findings
	msg := "fail-closed: thiếu findings"
}

deny contains msg if {
	some f in input.findings
	not f.severity
	msg := sprintf("fail-closed: finding thiếu severity (rule_id=%v)", [object.get(f, "rule_id", "?")])
}

# Chặn theo mức độ.
deny contains msg if {
	some f in input.findings
	f.severity in blocking_severity
	msg := sprintf("G1 chặn %s: %s tại %s", [f.severity, f.rule_id, object.get(f.location, "file", "?")])
}
