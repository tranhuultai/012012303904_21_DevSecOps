package main

import rego.v1

vuln_workflow := {
	"permissions": "write-all",
	"jobs": {
		"build": {
			"permissions": "write-all",
			"steps": [
				{"uses": "actions/checkout@v7", "run": "echo \"${{ github.event.pull_request.title }}\""},
			],
		},
	},
}

safe_workflow := {
	"permissions": "read",
	"jobs": {
		"build": {
			"permissions": {"contents": "read"},
			"steps": [
				{"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
				{"run": "echo hello"},
			],
		},
	},
}

test_workflow_vuln_denied if {
	# write-all (workflow) + write-all (job) + script injection + mutable uses
	count(deny) == 4 with input as vuln_workflow
}

test_workflow_clean_passes if {
	count(deny) == 0 with input as safe_workflow
}

has_rule(id) if {
	some msg in deny
	startswith(msg, id)
}

test_rule_ids_reported if {
	has_rule("GHA-WRITE-ALL") with input as vuln_workflow
	has_rule("GHA-SCRIPT-INJECTION") with input as vuln_workflow
	has_rule("GHA-UNPINNED-ACTION") with input as vuln_workflow
}

# Truyền giá trị qua env thì không bị coi là script injection.
test_env_indirection_passes if {
	inp := {"permissions": {"contents": "read"}, "jobs": {"build": {"steps": [{
		"env": {"PR_TITLE": "${{ github.event.pull_request.title }}"},
		"run": "echo \"${PR_TITLE}\"",
	}]}}}
	count(deny) == 0 with input as inp
}
