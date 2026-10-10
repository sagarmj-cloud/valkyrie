# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# tool_authz.rego — enforced at PEP 3 (gateway, before execution).
#
# Input shape (built by the gateway):
#   input.agent      { id, role }
#   input.principal  { sub, tenant_id }
#   input.tool       { name, risk_tier, data_classification, args }
#   input.customer   { id, diet, allergens[], budget_usd }   (optional, from context)
#   input.approval   { ticket_id }                            (optional)
#   input.budget     { usd_used, usd_limit }                  (optional)
#
# Data (from bundle):
#   data.roles[role]       { tools[], max_tier }
#   data.menu[item]        { price_usd, vegetarian, allergens[] }
#   data.limits            { max_delegation_depth, tip_rate }
package valkyrie.tool_authz

import rego.v1

default allow := false

# ---------------------------------------------------------------- allow
allow if {
	role := data.roles[input.agent.role]
	input.tool.name in role.tools
	input.tool.risk_tier <= role.max_tier
	count(deny_reason) == 0
}

# ---------------------------------------------------------------- deny reasons
# An agent may only call tools bound to its role.
deny_reason contains "tool_not_bound_to_role" if {
	not input.tool.name in data.roles[input.agent.role].tools
}

# Tier ceiling per role.
deny_reason contains "risk_tier_exceeds_role" if {
	input.tool.risk_tier > data.roles[input.agent.role].max_tier
}

# Tenant in arguments must match the caller's tenant (when present).
deny_reason contains "tenant_mismatch" if {
	input.tool.args.tenant_id
	input.tool.args.tenant_id != input.principal.tenant_id
}

# Fail closed: a cart without customer context cannot be checked, so it is denied.
deny_reason contains "missing_customer_context" if {
	input.tool.name == "orders.create_cart"
	not input.customer.allergens
}

# Dietary safety: no allergen in any cart for this customer.
deny_reason contains msg if {
	input.tool.name == "orders.create_cart"
	some item in input.tool.args.items
	some allergen in data.menu[item].allergens
	allergen in input.customer.allergens
	msg := sprintf("allergen_conflict: %s contains %s", [item, allergen])
}

# Dietary preference: vegetarian customers get vegetarian carts.
deny_reason contains msg if {
	input.tool.name == "orders.create_cart"
	input.customer.diet == "vegetarian"
	some item in input.tool.args.items
	data.menu[item].vegetarian == false
	msg := sprintf("diet_conflict: %s is not vegetarian", [item])
}

# Unknown menu items can never be carted.
deny_reason contains msg if {
	input.tool.name == "orders.create_cart"
	some item in input.tool.args.items
	not data.menu[item]
	msg := sprintf("unknown_item: %s", [item])
}

# Budget: cart total + tip must fit the customer's stated budget.
deny_reason contains msg if {
	input.tool.name == "orders.create_cart"
	input.customer.budget_usd
	total := cart_total(input.tool.args.items)
	with_tip := total * (1 + data.limits.tip_rate)
	with_tip > input.customer.budget_usd
	msg := sprintf("budget_exceeded: %.2f > %.2f", [with_tip, input.customer.budget_usd])
}

# Financial actions above the manifest threshold need a human ticket.
deny_reason contains "approval_required" if {
	input.tool.name == "payments.charge"
	input.tool.args.amount_usd > data.approval_threshold_usd
	not valid_ticket
}

# Raw card numbers never appear in arguments; only tokens.
deny_reason contains "raw_card_number_in_args" if {
	input.tool.name == "payments.charge"
	regex.match(`^[0-9]{13,19}$`, input.tool.args.payment_token)
}

# Per-run spend ceiling.
deny_reason contains "run_budget_exhausted" if {
	input.budget.usd_used >= input.budget.usd_limit
}

valid_ticket if {
	input.approval.ticket_id
	startswith(input.approval.ticket_id, "APR-")
}

cart_total(items) := sum([data.menu[i].price_usd | some i in items; data.menu[i]])

# ---------------------------------------------------------------- obligations
# Delivered to the gateway with the decision; enforced at PEP 4.
obligations["redact_fields"] := fields if {
	input.tool.data_classification == "pii"
	fields := data.pii_redact[input.agent.role]
}

obligations["max_rows"] := data.max_rows[input.agent.role]

obligations["ttl_seconds"] := 300

# ---------------------------------------------------------------- decision object
decision := {
	"allow": allow,
	"deny_reason": [r | some r in deny_reason],
	"obligations": obligations,
	"policy_version": data.policy_version,
}
