package main

import rego.v1

g1_ctx := {"today": "2026-10-24", "policy": "g1"}

finding(sev) := {"severity": sev, "rule_id": "R", "category": "sca", "location": {"file": "a.tf"}}

test_g1_chan_medium if {
	inp := {"context": g1_ctx, "findings": [finding("MEDIUM")], "exceptions": []}
	count(deny) > 0 with input as inp
}

test_g1_chan_critical if {
	inp := {"context": g1_ctx, "findings": [finding("CRITICAL")], "exceptions": []}
	count(deny) > 0 with input as inp
}

test_g1_bo_qua_low if {
	inp := {"context": g1_ctx, "findings": [finding("LOW")], "exceptions": []}
	count(deny) == 0 with input as inp
}

test_g1_findings_rong_qua_duoc if {
	inp := {"context": g1_ctx, "findings": [], "exceptions": []}
	count(deny) == 0 with input as inp
}

test_g1_failclosed_thieu_today if {
	inp := {"context": {"policy": "g1"}, "findings": [], "exceptions": []}
	count(deny) > 0 with input as inp
}

test_g1_failclosed_thieu_findings if {
	inp := {"context": g1_ctx, "exceptions": []}
	count(deny) > 0 with input as inp
}

test_g1_failclosed_finding_thieu_severity if {
	inp := {"context": g1_ctx, "findings": [{"rule_id": "R", "location": {"file": "a"}}], "exceptions": []}
	count(deny) > 0 with input as inp
}
