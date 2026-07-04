# METADATA
# scope: package
# title: Secrets Protection
# description: Stops agents from reading credential material.
# custom:
#   severity: CRITICAL
#   id: SECRETS-PROTECTION
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.secrets_protection

import rego.v1

sensitive_patterns := [
	".env",
	"id_rsa",
	"id_ed25519",
	".pem",
	".p12",
	"credentials", # ~/.aws/credentials and friends
	".kube/config",
	".npmrc",
	".pypirc",
]

deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name in {"Read", "Grep", "Glob"}
	path := lower(object.get(input.tool_input, "file_path", object.get(input.tool_input, "pattern", "")))
	some pattern in sensitive_patterns
	contains(path, pattern)
	decision := {
		"rule_id": "SECRETS-PROTECTION-001",
		"reason": sprintf("Blocked access to potential credential material (%s)", [pattern]),
		"severity": "CRITICAL",
	}
}

deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	some pattern in sensitive_patterns
	contains(cmd, pattern)
	regex.match(`\b(cat|less|head|tail|grep|strings|base64)\b`, cmd)
	decision := {
		"rule_id": "SECRETS-PROTECTION-002",
		"reason": sprintf("Blocked shell read of potential credential material (%s)", [pattern]),
		"severity": "CRITICAL",
	}
}
