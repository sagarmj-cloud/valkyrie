# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# data_egress.rego — enforced at PEP 4 (gateway, after execution).
package valkyrie.data_egress

import rego.v1

default allow := false

allow if not blocked

# Confidential results never leave the trust boundary.
blocked if {
	input.result.classification == "confidential"
	input.destination.zone == "external"
}

deny_reason contains "confidential_egress_blocked" if blocked

decision := {"allow": allow, "deny_reason": [r | some r in deny_reason], "policy_version": data.policy_version}
