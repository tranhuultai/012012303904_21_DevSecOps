package main

import rego.v1

# G0: mốc đo nhiễu — pipeline chạy nhưng gate không chặn gì.
# Giữ "deny" ở dạng tập rỗng để Conftest và test tham chiếu được.
deny contains msg if {
	false
	msg := "g0 không bao giờ chặn"
}
