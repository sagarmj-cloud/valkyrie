# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""payments — tokenized card charges (tier 3, financial). Python adapter."""
import itertools

from valkyrie.server import make_server, serve

mcp = make_server("payments", scope="payments:charge", instructions="Charge tokenized payment methods.")
_seq = itertools.count(9001)


@mcp.tool(name="payments.charge")
def charge(order_id: str, amount_usd: float, payment_token: str) -> dict:
    """Charge a tokenized payment method for an order. Never accepts raw card numbers."""
    if not payment_token.startswith("tok_"):
        raise ValueError("payment_token must be a token, not a card number")
    return {"charge_id": f"ch-{next(_seq)}", "order_id": order_id, "amount_usd": amount_usd, "status": "captured"}


if __name__ == "__main__":
    serve(mcp, port=8104)
