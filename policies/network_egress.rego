# METADATA
# scope: package
# title: Network Egress
# description: Blocks fetch-and-execute pipelines and confirms outbound uploads.
# custom:
#   severity: HIGH
#   id: NET-EGRESS
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.network_egress

import rego.v1

# curl | sh runs code straight off the network with no review step. The
# classic installer one-liner is exactly the pattern a compromised page
# abuses, so it never runs unsupervised.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`(curl|wget)[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`, cmd)
	decision := {
		"rule_id": "NET-EGRESS-001",
		"reason": "Piping a download into a shell executes unreviewed remote code",
		"severity": "CRITICAL",
	}
}

# Same trick through process substitution or a python pipe.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`(ba|z)?sh\s+<\(\s*(curl|wget)|(curl|wget)[^|;]*\|\s*python`, cmd)
	decision := {
		"rule_id": "NET-EGRESS-002",
		"reason": "Fetch-and-execute pattern blocked",
		"severity": "CRITICAL",
	}
}

# Sending local file contents to a remote endpoint is exfiltration until a
# human says otherwise.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	contains(cmd, "curl")
	regex.match(`--upload-file|--data-binary\s+@|-d\s+@|-f\s+[^\s]*=@|-t\s`, cmd)
	decision := {
		"rule_id": "NET-EGRESS-003",
		"reason": "Agent wants to upload local file contents to a remote endpoint.",
		"question": "Allow this upload?",
		"severity": "HIGH",
	}
}
