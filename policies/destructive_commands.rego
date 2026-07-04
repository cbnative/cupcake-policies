# METADATA
# scope: package
# title: Destructive Commands
# description: Halts catastrophic commands, asks on merely dangerous ones.
# custom:
#   severity: CRITICAL
#   id: DESTRUCTIVE
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.destructive_commands

import rego.v1

# Catastrophic and unrecoverable: full stop, not overridable.
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)[a-z]*\s+(/|~|\$home)(\s|$)`, cmd)
	decision := {
		"rule_id": "DESTRUCTIVE-001",
		"reason": "Recursive delete of / or home. No.",
		"severity": "CRITICAL",
	}
}

# Dangerous but sometimes legitimate: require confirmation.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)`, cmd)
	not regex.match(`rm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)[a-z]*\s+(/|~|\$home)(\s|$)`, cmd)
	decision := {
		"rule_id": "DESTRUCTIVE-002",
		"reason": "Recursive force delete. Confirm the target is right.",
		"severity": "HIGH",
	}
}

deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`chmod\s+(-[a-z]+\s+)*777\s+/(\s|$)|mkfs|dd\s+.*of=/dev/`, cmd)
	decision := {
		"rule_id": "DESTRUCTIVE-003",
		"reason": "System-level destructive command blocked",
		"severity": "CRITICAL",
	}
}
