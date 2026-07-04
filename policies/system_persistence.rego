# METADATA
# scope: package
# title: System Persistence
# description: Watches changes that outlive the agent session.
# custom:
#   severity: HIGH
#   id: SYS-PERSIST
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.system_persistence

import rego.v1

shell_rc_files := [
	".zshrc",
	".bashrc",
	".bash_profile",
	".zprofile",
	".profile",
]

# Everything the agent does normally dies with the session. A cron job, a
# service, or a line in your shell rc keeps running after you close the lid,
# which is also how malware persists. Sudoers grants power instead, so that
# one is a hard no.

# crontab -r silently wipes every scheduled job you have.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`crontab\s+-r\b`, cmd)
	decision := {
		"rule_id": "SYS-PERSIST-001",
		"reason": "crontab -r removes every cron job with no undo",
		"severity": "CRITICAL",
	}
}

# Installing anything that starts on boot or on a schedule needs a human.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`crontab\s+(?:-e\b|[^-\s])|systemctl\s+enable|launchctl\s+(load|bootstrap)`, cmd)
	decision := {
		"rule_id": "SYS-PERSIST-002",
		"reason": "This installs something that keeps running after the session ends.",
		"question": "Allow this persistent change?",
		"severity": "HIGH",
	}
}

# Shell rc edits change every future terminal. Legitimate sometimes (PATH
# entries), so confirm instead of blocking.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name in {"Edit", "Write"}
	path := lower(object.get(input, "resolved_file_path", object.get(input.tool_input, "file_path", "")))
	some rc in shell_rc_files
	endswith(path, rc)
	decision := {
		"rule_id": "SYS-PERSIST-003",
		"reason": "This edits a shell startup file that runs in every future terminal.",
		"question": "Allow this shell config edit?",
		"severity": "HIGH",
	}
}

# Sudoers decides who is root. No agent business, ever.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name in {"Edit", "Write"}
	path := lower(object.get(input, "resolved_file_path", object.get(input.tool_input, "file_path", "")))
	contains(path, "sudoers")
	decision := {
		"rule_id": "SYS-PERSIST-004",
		"reason": "Sudoers changes grant root. Not for agents.",
		"severity": "CRITICAL",
	}
}
