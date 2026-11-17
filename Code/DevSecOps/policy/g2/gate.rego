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
	"CKV_AWS_382", "AWS-0104", # security group unrestricted egress (Checkov / Trivy)
	"CKV_DOCKER_1", "CKV_DOCKER_3", "CKV_DOCKER_4", "CKV_DOCKER_7", # SSH/latest tag/non-root/remote ADD
	"CKV_K8S_16", # privileged
	"CKV_K8S_14", # image không ghim digest
	"KSV-0111", # ServiceAccount cluster-admin
	"KSV-0109", # mật khẩu trong ConfigMap
	"CKV2_GHA_1", # token write-all
	"CKV_GHA_2", # script injection trong run
	"DSEC_GHA_001", # action reference không ghim SHA 40 ký tự
	"DSEC_GHA_002", # quyền GitHub Actions write-all
	"DSEC_GHA_003", # nội suy github.event không tin cậy vào run
}

# Mức WARN có chủ đích cho các thiếu sót cần xem xét nhưng không đủ cơ sở
# chặn phát hành ngay. Gom chúng thành một advisory để không tạo một warning
# riêng cho mỗi engine/rule trùng lặp trong baseline.
iac_warn_controls := {
	"CKV_AWS_21", # S3 versioning (D20)
	"CKV_AWS_129", "CKV_AWS_145", "CKV_AWS_161", "CKV_AWS_226", "CKV_AWS_293",
	"CKV_K8S_11", "CKV_K8S_43", # resource limits / image pinning (D22-D23)
	"CKV_K8S_35", # tránh đưa secret vào biến môi trường container
	"CKV2_AWS_11", "CKV2_AWS_12", "CKV2_AWS_30",
	"AWS-0132", # S3 CMK; AWS-managed encryption vẫn đang bật
	"AWS-0178", "AWS-0077", "AWS-0176", "AWS-0177", "AWS-0090",
	"KSV-0125", # registry tin cậy cho image Kubernetes
	"CKV_GHA_7", # workflow_dispatch inputs có chủ đích cho bộ thí nghiệm, cần giữ để dispatch D/C/N/E3
}

sast_block_severity := {"CRITICAL", "HIGH"}

severity_cap_days := {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 90, "INFO": 90}
severity_rank := {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

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
	e.reason
	e.match.rule_id
	e.match.resource
	e.owner != e.approved_by
	e.created <= input.context.today
	e.expires > input.context.today
	date_span(e.created, e.expires) <= object.get(severity_cap_days, e.severity, 0)
}

excused(f) if {
	some e in input.exceptions
	valid_exception(e)
	e.match.rule_id == f.rule_id
	e.match.resource == object.get(f.location, "resource", "")
	object.get(severity_rank, e.severity, -1) >= object.get(severity_rank, f.severity, 5)
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

# ---- CVE có xác suất bị khai thác cao theo EPSS (>= 0.10, tức >= 10%) ----
deny contains msg if {
	some f in input.findings
	f.epss >= 0.10
	not excused(f)
	msg := sprintf("G2 BLOCK EPSS cao (%.2f): %s", [f.epss, f.rule_id])
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
	not valid_exception(e)
	msg := sprintf("G2 BLOCK ngoại lệ không hợp lệ hoặc hết hạn: %s", [object.get(e, "id", "?")])
}

# ---- Cảnh báo, không chặn ----
warn contains msg if {
	some f in input.findings
	f.category == "sast"
	f.severity == "MEDIUM"
	msg := sprintf("WARN SAST MEDIUM cần đánh giá: %s", [f.rule_id])
}

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
	some f in input.findings
	f.epss >= 0.01
	f.epss < 0.10
	not excused(f)
	msg := sprintf("WARN EPSS trung bình (%.2f): %s", [f.epss, f.rule_id])
}

# ---- IaC/K8s baseline findings cần review; giữ tối đa một advisory tổng hợp ----
warn contains msg if {
	controls := {f.rule_id |
		some f in input.findings
		f.rule_id in iac_warn_controls
		not excused(f)
	}
	count(controls) > 0
	sorted_controls := sort([rule_id | some rule_id in controls])
	msg := sprintf("WARN IaC controls require review: %s", [concat(", ", sorted_controls)])
}

warn contains msg if {
	some e in input.exceptions
	valid_exception(e)
	date_span(input.context.today, e.expires) <= 7
	msg := sprintf("WARN ngoại lệ sắp hết hạn: %s", [object.get(e, "id", "?")])
}
