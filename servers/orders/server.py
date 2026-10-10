# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""orders — cart and order MCP server (tier 2, write). Python adapter."""
import itertools

from valkyrie.server import make_server, serve

mcp = make_server("orders", scope="orders:write", instructions="Create carts and place orders.")

PRICES = {"Pesto Pasta": 16.00, "Margherita Pizza": 18.00, "Pepperoni Pizza": 19.00, "Arrabbiata Penne": 15.00, "Truffle Mushroom Pizza": 24.00}
TIP_RATE = 0.15
_carts: dict[str, dict] = {}
_orders: dict[str, dict] = {}
_seq = itertools.count(4821)


@mcp.tool(name="orders.create_cart")
def create_cart(customer_id: str, items: list[str]) -> dict:
    """Create a cart for a customer. Returns cart_id, subtotal, tip and total in USD."""
    subtotal = sum(PRICES[i] for i in items)
    cart_id = f"cart-{next(_seq)}"
    _carts[cart_id] = {"cart_id": cart_id, "customer_id": customer_id, "items": items,
                       "subtotal_usd": round(subtotal, 2), "tip_usd": round(subtotal * TIP_RATE, 2),
                       "total_usd": round(subtotal * (1 + TIP_RATE), 2)}
    return _carts[cart_id]


@mcp.tool(name="orders.place_order")
def place_order(cart_id: str, deliver_by: str | None = None) -> dict:
    """Place an order for an existing cart. Returns order_id and total."""
    cart = _carts[cart_id]
    order_id = f"ord-{next(_seq)}"
    _orders[order_id] = {"order_id": order_id, **cart, "deliver_by": deliver_by, "status": "placed"}
    return _orders[order_id]


if __name__ == "__main__":
    serve(mcp, port=8103)
