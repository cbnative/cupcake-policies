# METADATA
# scope: package
# title: Package Publish
# description: Publishing to a registry is a public action; a human confirms it.
# custom:
#   severity: HIGH
#   id: PKG-PUBLISH
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.package_publish

import rego.v1

# Once a version is on a public registry it is cached, mirrored and installed
# by strangers. Unpublishing never fully undoes it.
publish_commands := [
	`npm\s+publish`,
	`yarn\s+publish`,
	`twine\s+upload`,
	`docker\s+push`,
	`podman\s+push`,
	`helm\s+push`,
	`cargo\s+publish`,
	`gem\s+push`,
	`gh\s+release\s+create`,
]

ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	some pattern in publish_commands
	regex.match(pattern, cmd)
	decision := {
		"rule_id": "PKG-PUBLISH-001",
		"reason": "Publishing to a registry is public and effectively permanent.",
		"question": "Publish this artifact?",
		"severity": "HIGH",
	}
}
