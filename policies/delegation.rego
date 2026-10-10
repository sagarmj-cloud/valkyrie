# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# delegation.rego — enforced at PEP 2 (supervisor → specialist).
package valkyrie.delegation

import rego.v1

default allow := false

allow if {
	input.target.tenant_id == input.caller.tenant_id
	input.target.trust_level >= input.task.required_trust
	count(input.chain) < data.limits.max_delegation_depth
	not loop_detected
	not budget_exceeded
}

loop_detected if input.target.id in input.chain

budget_exceeded if {
	input.budget.tokens_used + input.task.est_tokens > input.budget.token_limit
}

deny_reason contains "tenant_mismatch" if input.target.tenant_id != input.caller.tenant_id
deny_reason contains "insufficient_trust" if input.target.trust_level < input.task.required_trust
deny_reason contains "delegation_too_deep" if count(input.chain) >= data.limits.max_delegation_depth
deny_reason contains "delegation_loop" if loop_detected
deny_reason contains "token_budget_exceeded" if budget_exceeded

decision := {"allow": allow, "deny_reason": [r | some r in deny_reason], "policy_version": data.policy_version}
