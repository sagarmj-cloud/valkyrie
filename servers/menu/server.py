# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""menu — menu catalogue MCP server (tier 0, public). Python adapter."""
from valkyrie.server import make_server, serve

mcp = make_server("menu", scope="menu:read", instructions="Search the restaurant menu.")

MENU = [
    {"item": "Pesto Pasta", "price_usd": 16.00, "vegetarian": True, "allergens": ["tree_nuts", "dairy", "gluten"], "prep_min": 15},
    {"item": "Margherita Pizza", "price_usd": 18.00, "vegetarian": True, "allergens": ["dairy", "gluten"], "prep_min": 20},
    {"item": "Pepperoni Pizza", "price_usd": 19.00, "vegetarian": False, "allergens": ["dairy", "gluten"], "prep_min": 20},
    {"item": "Arrabbiata Penne", "price_usd": 15.00, "vegetarian": True, "allergens": ["gluten"], "prep_min": 12},
    {"item": "Truffle Mushroom Pizza", "price_usd": 24.00, "vegetarian": True, "allergens": ["dairy", "gluten"], "prep_min": 25},
]


@mcp.tool(name="menu.search_menu")
def search_menu(query: str = "", vegetarian: bool | None = None, max_price_usd: float | None = None) -> dict:
    """Search the menu by free text and dietary filters. Returns matching items with price and allergens."""
    out = []
    for m in MENU:
        if query and query.lower() not in m["item"].lower() and query.lower() not in ("pizza", "pasta", "dinner"):
            continue
        if vegetarian is not None and m["vegetarian"] != vegetarian:
            continue
        if max_price_usd is not None and m["price_usd"] > max_price_usd:
            continue
        out.append(m)
    return {"items": out}


if __name__ == "__main__":
    serve(mcp, port=8102)
