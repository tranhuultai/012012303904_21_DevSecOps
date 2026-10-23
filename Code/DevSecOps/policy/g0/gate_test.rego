package main

import rego.v1

g0_ctx := {"today": "2026-10-24", "policy": "g0"}

# Dù có finding CRITICAL, G0 vẫn không chặn.
test_g0_khong_chan_gi if {
	inp := {
		"context": g0_ctx,
		"findings": [{"severity": "CRITICAL", "rule_id": "X", "category": "sca", "location": {"file": "a"}}],
		"exceptions": [],
	}
	count(deny) == 0 with input as inp
}
