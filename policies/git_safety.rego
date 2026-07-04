# METADATA
# scope: package
# title: Git Safety
# description: Guardrails for git operations performed by AI coding agents.
# custom:
#   severity: HIGH
#   id: GIT-SAFETY
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.git_safety

import rego.v1

# Never force-push to a protected branch.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	contains(cmd, "git push")
	regex.match(`(--force|-f)\b`, cmd)
	regex.match(`\b(main|master|production)\b`, cmd)
	decision := {
		"rule_id": "GIT-SAFETY-001",
		"reason": "Force-push to a protected branch is not allowed",
		"severity": "CRITICAL",
	}
}

# Pushing is a publishing action: require human confirmation.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	contains(cmd, "git push")
	not regex.match(`(--force|-f)\b`, cmd)
	decision := {
		"rule_id": "GIT-SAFETY-002",
		"reason": "Agent wants to push commits. Review before it publishes.",
		"severity": "MEDIUM",
	}
}

# Rewriting history unsupervised leads to lost work.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`git reset --hard|git clean -[a-z]*f`, cmd)
	decision := {
		"rule_id": "GIT-SAFETY-003",
		"reason": "History-destroying git command blocked; run it yourself if intended",
		"severity": "HIGH",
	}
}
