package main

import rego.v1

# G2: chặn khi hội đủ tác động cao, phát hiện đáng tin, sửa được ngay.
# Thiếu một điều kiện thì chỉ cảnh báo; secret luôn chặn; tầng IaC theo khóa kiểm soát.

# Khóa kiểm soát tác động cao (BLOCK), không dựa mức công cụ tự chấm.
iac_block_controls := {
	"CKV_AWS_24", "CKV_AWS_25", # cổng 22/3389 mở cho 0.0.0.0/0
	"CKV_AWS_1", "CKV_AWS_49", "CKV_AWS_62", "CKV_AWS_63", # IAM * trên *
	"CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56", # S3 public
	"CKV_AWS_17", # RDS public
	"CKV_AWS_16", # RDS chưa mã hóa
	"CKV_K8S_16", # privileged
	"CKV_K8S_14", "CKV_K8S_43", # image không ghim digest
	"KSV-0111", # ServiceAccount cluster-admin
	"KSV-0109", # mật khẩu trong ConfigMap
	"CKV2_GHA_1", # token write-all
	"CKV_GHA_2", # script injection trong run
}

sast_block_severity := {"CRITICAL", "HIGH"}

severity_cap_days := {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 90, "INFO": 90}

# ---- Fail-closed: thiếu dữ liệu bắt buộc thì chặn ----
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

# ---- Ngoại lệ hợp lệ ----
date_span(d_from, d_to) := n if {
	t_from := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d_from]))
	t_to := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [d_to]))
	n := (t_to - t_from) / (((((1000 * 1000) * 1000) * 60) * 60) * 24)
}

valid_exception(e) if {
	e.owner
	e.approved_by
	trim_space(e.reason) != ""
	e.match.rule_id
	e.match.resource
	e.owner != e.approved_by
	e.created <= input.context.today # đã bắt đầu, không phải ngày tương lai
	e.created <= e.expires # span không âm
	e.expires >= input.context.today # chưa quá hạn
	date_span(e.created, e.expires) <= object.get(severity_cap_days, e.severity, 0)
}

# Ngoại lệ chỉ miễn trừ finding cùng rule_id, resource VÀ cùng mức độ
# (tránh khai mức thấp để lấy trần dài cho finding mức cao).
excused(f) if {
	some e in input.exceptions
	valid_exception(e)
	e.match.rule_id == f.rule_id
	e.match.resource == object.get(f.location, "resource", "")
	e.severity == f.severity
}

# ---- Secret luôn chặn, không ngoại lệ ----
deny contains msg if {
	some f in input.findings
	f.category == "secret"
	msg := sprintf("G2 BLOCK secret: %s tại %s", [f.rule_id, object.get(f.location, "file", "?")])
}

# ---- CVE thuộc KEV (mọi mức) ----
deny contains msg if {
	some f in input.findings
	f.kev == true
	not excused(f)
	msg := sprintf("G2 BLOCK KEV: %s", [f.rule_id])
}

# ---- SCA/image CRITICAL|HIGH có bản vá, khớp tin cậy cao ----
deny contains msg if {
	some f in input.findings
	f.category in {"sca", "image"}
	f.severity in {"CRITICAL", "HIGH"}
	f.fix_available == true
	f.match_confidence == "high"
	not excused(f)
	msg := sprintf("G2 BLOCK CVE sửa được: %s (%s)", [f.rule_id, f.severity])
}

# ---- IaC/K8s/CI theo khóa kiểm soát tác động cao ----
deny contains msg if {
	some f in input.findings
	f.rule_id in iac_block_controls
	not excused(f)
	msg := sprintf("G2 BLOCK cấu hình: %s", [f.rule_id])
}

# ---- SAST injection/deserialization/command injection (mức cao) ----
deny contains msg if {
	some f in input.findings
	f.category == "sast"
	f.severity in sast_block_severity
	not excused(f)
	msg := sprintf("G2 BLOCK SAST: %s (%s)", [f.rule_id, f.severity])
}

# ---- Ngoại lệ không hợp lệ thì chặn ----
deny contains msg if {
	some e in input.exceptions
	e.expires < input.context.today
	msg := sprintf("G2 BLOCK ngoại lệ hết hạn: %s", [object.get(e, "id", "?")])
}

deny contains msg if {
	some e in input.exceptions
	e.owner == e.approved_by
	msg := sprintf("G2 BLOCK ngoại lệ owner trùng approved_by: %s", [object.get(e, "id", "?")])
}

deny contains msg if {
	some e in input.exceptions
	not e.reason
	msg := sprintf("G2 BLOCK ngoại lệ thiếu lý do: %s", [object.get(e, "id", "?")])
}

# ---- Cảnh báo, không chặn ----
warn contains msg if {
	some f in input.findings
	f.category in {"sca", "image"}
	f.severity == "HIGH"
	f.fix_available == false
	msg := sprintf("WARN HIGH chưa có bản vá: %s", [f.rule_id])
}

warn contains msg if {
	some f in input.findings
	f.category in {"sca", "image"}
	f.severity == "MEDIUM"
	f.fix_available == true
	msg := sprintf("WARN MEDIUM có bản vá: %s", [f.rule_id])
}

warn contains msg if {
	some e in input.exceptions
	valid_exception(e)
	date_span(input.context.today, e.expires) <= 7
	msg := sprintf("WARN ngoại lệ sắp hết hạn: %s", [object.get(e, "id", "?")])
}
