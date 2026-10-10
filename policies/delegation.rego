# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# delegation.rego — enforced at PEP 2 (supervisor → specialist) by the gateway's
# POST /v1/delegate: input.caller and input.chain come from the verified token,
# input.target / task / budget from the request. tool_authz.rego re-checks chain
# integrity (loop, depth) on every tool call.
package valkyrie.delegation

import rego.v1

default allow := false

allow if {
	caller_may_delegate
	data.roles[input.target.role]
	input.target.tenant_id == input.caller.tenant_id
	input.target.trust_level >= input.task.required_trust
	count(input.chain) < data.limits.max_delegation_depth
	not loop_detected
	not budget_exceeded
}

# Delegation is a capability granted per role in the registry (valkyriectl
# role bind --can-delegate), carried into the bundle as roles[<role>].can_delegate.
caller_may_delegate if data.roles[input.caller.role].can_delegate == true

loop_detected if input.target.id in input.chain

budget_exceeded if {
	input.budget.tokens_used + input.task.est_tokens > input.budget.token_limit
}

deny_reason contains "caller_may_not_delegate" if not caller_may_delegate

# The gateway issues the target an identity carrying this role; it must exist.
deny_reason contains "unknown_target_role" if not data.roles[input.target.role]

deny_reason contains "tenant_mismatch" if input.target.tenant_id != input.caller.tenant_id
deny_reason contains "insufficient_trust" if input.target.trust_level < input.task.required_trust
deny_reason contains "delegation_too_deep" if count(input.chain) >= data.limits.max_delegation_depth
deny_reason contains "delegation_loop" if loop_detected
deny_reason contains "token_budget_exceeded" if budget_exceeded

decision := {"allow": allow, "deny_reason": [r | some r in deny_reason], "policy_version": data.policy_version}
