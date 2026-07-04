# METADATA
# scope: package
# title: Package Install
# description: Confirms installs that bypass the default registry.
# custom:
#   severity: MEDIUM
#   id: PKG-INSTALL
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.package_install

import rego.v1

# Installing from a raw URL or a git ref skips the registry entirely: no
# version pinning, no audit trail, whatever is at that ref right now.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`(pip3?\s+install|npm\s+(install|i|add)|yarn\s+add)[^|;]*\s(https?://|git\+|github:)`, cmd)
	decision := {
		"rule_id": "PKG-INSTALL-001",
		"reason": "Install from a URL or git ref skips the registry and its audit trail.",
		"question": "Install from this source?",
		"severity": "MEDIUM",
	}
}

# Pointing the package manager at a different index is the setup step of a
# dependency confusion attack. Sometimes legitimate (internal mirror), so ask.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`(--index-url|--extra-index-url|--registry)[=\s]`, cmd)
	decision := {
		"rule_id": "PKG-INSTALL-002",
		"reason": "This command overrides the default package registry.",
		"question": "Use this registry?",
		"severity": "MEDIUM",
	}
}
