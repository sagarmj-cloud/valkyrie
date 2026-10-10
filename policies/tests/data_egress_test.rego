# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
package valkyrie.data_egress_test

import rego.v1

import data.valkyrie.data_egress

test_internal_confidential_ok if {
	data_egress.allow with input as {"result": {"classification": "confidential"}, "destination": {"zone": "internal"}}
}

test_external_confidential_blocked if {
	not data_egress.allow with input as {"result": {"classification": "confidential"}, "destination": {"zone": "external"}}
}
