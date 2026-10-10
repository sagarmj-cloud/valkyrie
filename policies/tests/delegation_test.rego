# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
package valkyrie.delegation_test

import rego.v1

import data.valkyrie.delegation

ok := {
	"caller": {"id": "concierge-01", "tenant_id": "acme"},
	"target": {"id": "menu-01", "tenant_id": "acme", "trust_level": 2},
	"task": {"required_trust": 1, "est_tokens": 2000},
	"chain": ["concierge-01"],
	"budget": {"tokens_used": 10000, "token_limit": 100000},
}

test_delegation_allowed if delegation.allow with input as ok

test_loop_denied if {
	inp := object.union(ok, {"chain": ["concierge-01", "menu-01"]})
	"delegation_loop" in delegation.deny_reason with input as inp
}

test_too_deep_denied if {
	inp := object.union(ok, {"chain": ["a", "b", "c", "d"]})
	"delegation_too_deep" in delegation.deny_reason with input as inp
}

test_cross_tenant_denied if {
	inp := object.union(ok, {"target": {"id": "menu-01", "tenant_id": "other", "trust_level": 2}})
	"tenant_mismatch" in delegation.deny_reason with input as inp
}

test_token_budget_denied if {
	inp := object.union(ok, {"budget": {"tokens_used": 99000, "token_limit": 100000}})
	"token_budget_exceeded" in delegation.deny_reason with input as inp
}
