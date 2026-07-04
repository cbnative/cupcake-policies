# METADATA
# scope: package
# title: Kubernetes Safety
# description: Keeps agents from deleting cluster resources at scale.
# custom:
#   severity: HIGH
#   id: K8S-SAFETY
#   routing:
#     required_events: ["PreToolUse"]
package cupcake.policies.kubernetes_safety

import rego.v1

# Deleting a namespace takes everything inside it along. Never unsupervised.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`kubectl\s+delete\s+(ns|namespace)\b`, cmd)
	decision := {
		"rule_id": "K8S-SAFETY-001",
		"reason": "Namespace deletion wipes every resource inside it. Do this one yourself.",
		"severity": "CRITICAL",
	}
}

# Bulk deletes: --all and --all-namespaces turn a typo into an outage.
deny contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	contains(cmd, "kubectl delete")
	regex.match(`\s(--all|--all-namespaces|-a)(\s|$)`, cmd)
	decision := {
		"rule_id": "K8S-SAFETY-002",
		"reason": "Bulk delete across resources or namespaces blocked",
		"severity": "CRITICAL",
	}
}

# A single targeted delete is sometimes what you asked for. Confirm it.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	contains(cmd, "kubectl delete")
	not regex.match(`kubectl\s+delete\s+(ns|namespace)\b`, cmd)
	not regex.match(`\s(--all|--all-namespaces|-a)(\s|$)`, cmd)
	decision := {
		"rule_id": "K8S-SAFETY-003",
		"reason": "Agent wants to delete a cluster resource.",
		"question": "Delete this resource?",
		"severity": "MEDIUM",
	}
}

# Uninstalling a release or draining a node changes what is running. Confirm.
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"
	cmd := lower(input.tool_input.command)
	regex.match(`helm\s+uninstall|kubectl\s+(drain|cordon)\b`, cmd)
	decision := {
		"rule_id": "K8S-SAFETY-004",
		"reason": "This changes what is running on the cluster.",
		"question": "Proceed with this cluster operation?",
		"severity": "MEDIUM",
	}
}
