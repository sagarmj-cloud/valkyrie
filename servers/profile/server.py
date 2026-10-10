# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""profile — customer profile MCP server (tier 1, PII). Python adapter."""
from valkyrie.server import make_server, serve

mcp = make_server("profile", scope="profile:read", instructions="Customer dietary profiles and contact details.")

CUSTOMERS = {
    "c-42": {"customer_id": "c-42", "name": "Jane Doe", "diet": "vegetarian", "allergens": ["tree_nuts"],
             "budget_usd": 25, "phone": "+1-925-555-0100", "email": "jane@example.com",
             "address": {"line_1": "1 Main St", "address_line_2": "Apt 4", "city": "Pleasanton", "zip": "94566"},
             "payment_token": "tok_visa4242", "taste_history": ["Margherita Pizza", "Arrabbiata Penne"]},
}


@mcp.tool(name="profile.get_preferences")
def get_preferences(customer_id: str) -> dict:
    """Return the customer's dietary profile, allergens, budget and contact details."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        raise ValueError(f"unknown customer {customer_id}")
    return c


if __name__ == "__main__":
    serve(mcp, port=8101)
