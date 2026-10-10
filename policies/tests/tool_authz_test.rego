# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
package valkyrie.tool_authz_test

import rego.v1

import data.valkyrie.tool_authz

base := {
	"agent": {"id": "ordering-01", "role": "ordering"},
	"principal": {"sub": "jane.doe", "tenant_id": "acme"},
	"customer": {"id": "c-42", "diet": "vegetarian", "allergens": ["tree_nuts"], "budget_usd": 25},
	"budget": {"usd_used": 0.4, "usd_limit": 5},
}

cart(items) := object.union(base, {"tool": {
	"name": "orders.create_cart", "risk_tier": 2, "data_classification": "confidential",
	"args": {"customer_id": "c-42", "items": items},
}})

test_margherita_allowed if {
	tool_authz.allow with input as cart(["Margherita Pizza"])
}

test_pesto_denied_for_nut_allergy if {
	not tool_authz.allow with input as cart(["Pesto Pasta"])
	"allergen_conflict: Pesto Pasta contains tree_nuts" in tool_authz.deny_reason with input as cart(["Pesto Pasta"])
}

test_pepperoni_denied_for_vegetarian if {
	"diet_conflict: Pepperoni Pizza is not vegetarian" in tool_authz.deny_reason with input as cart(["Pepperoni Pizza"])
}

test_unknown_item_denied if {
	"unknown_item: Unicorn Steak" in tool_authz.deny_reason with input as cart(["Unicorn Steak"])
}

test_budget_exceeded if {
	# 24.00 * 1.15 = 27.60 > 25
	not tool_authz.allow with input as cart(["Truffle Mushroom Pizza"])
	some r in tool_authz.deny_reason with input as cart(["Truffle Mushroom Pizza"])
	startswith(r, "budget_exceeded")
}

test_cart_without_customer_context_denied if {
	inp := object.remove(cart(["Margherita Pizza"]), ["customer"])
	not tool_authz.allow with input as inp
	"missing_customer_context" in tool_authz.deny_reason with input as inp
}

test_menu_agent_cannot_cart if {
	inp := object.union(cart(["Margherita Pizza"]), {"agent": {"id": "menu-01", "role": "menu"}})
	not tool_authz.allow with input as inp
	"tool_not_bound_to_role" in tool_authz.deny_reason with input as inp
}

test_tenant_mismatch if {
	inp := object.union(base, {"tool": {
		"name": "delivery.quote_eta", "risk_tier": 0, "data_classification": "internal",
		"args": {"order_id": "o-1", "tenant_id": "evil-corp"},
	}})
	"tenant_mismatch" in tool_authz.deny_reason with input as inp
}

charge(amount, token) := object.union(base, {"tool": {
	"name": "payments.charge", "risk_tier": 3, "data_classification": "confidential",
	"args": {"order_id": "o-1", "amount_usd": amount, "payment_token": token},
}})

test_small_charge_allowed if {
	tool_authz.allow with input as charge(21.40, "tok_abc123")
}

test_large_charge_needs_approval if {
	not tool_authz.allow with input as charge(120, "tok_abc123")
	"approval_required" in tool_authz.deny_reason with input as charge(120, "tok_abc123")
}

test_large_charge_with_ticket_allowed if {
	inp := object.union(charge(120, "tok_abc123"), {"approval": {"ticket_id": "APR-7781"}})
	tool_authz.allow with input as inp
}

test_raw_card_number_denied if {
	"raw_card_number_in_args" in tool_authz.deny_reason with input as charge(10, "4111111111111111")
}

test_run_budget_exhausted if {
	inp := object.union(cart(["Margherita Pizza"]), {"budget": {"usd_used": 5, "usd_limit": 5}})
	"run_budget_exhausted" in tool_authz.deny_reason with input as inp
}

test_pii_obligations_for_profile_read if {
	inp := object.union(base, {
		"agent": {"id": "concierge-01", "role": "concierge"},
		"tool": {"name": "profile.get_preferences", "risk_tier": 1, "data_classification": "pii", "args": {"customer_id": "c-42"}},
	})
	tool_authz.allow with input as inp
	tool_authz.obligations.redact_fields == ["phone", "email", "address_line_2"] with input as inp
	tool_authz.obligations.max_rows == 100 with input as inp
}

test_decision_object_shape if {
	d := tool_authz.decision with input as cart(["Pesto Pasta"])
	d.allow == false
	count(d.deny_reason) == 1
	d.policy_version == "v2026.10.1"
}
