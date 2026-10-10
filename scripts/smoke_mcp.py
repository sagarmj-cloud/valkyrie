#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Exercise the gateway's MCP-native face (/mcp) the way an IDE client would:
initialize, tools/list (policy-filtered), tools/call (allowed and denied)."""
import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from valkyrie import mint_dev_token

GATEWAY = os.environ.get("VALKYRIE_URL", "http://127.0.0.1:8080")
SECRET = os.environ.get("VALKYRIE_AUTH_SECRET", "dev-secret-change-me")


async def session_for(role: str):
    token = mint_dev_token(SECRET, sub="dev@example.com", tenant_id="acme", agent_id=f"ide-{role}", agent_role=role)
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    return streamable_http_client(f"{GATEWAY}/mcp", http_client=http)


async def main() -> int:
    failures = 0
    # 1. menu role sees only menu tools
    async with (await session_for("menu")) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            print("menu role sees:", names)
            failures += names != ["menu.search_menu"]
    # 2. ordering role: allowed call, then a policy deny surfaces as a JSON-RPC error with the reason
    async with (await session_for("ordering")) as (r, w, *_):
        async with ClientSession(r, w) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            print("ordering role sees:", names)
            failures += "orders.create_cart" not in names or "profile.get_preferences" in names
            ok = await s.call_tool("delivery.quote_eta", {"order_id": "ord-1"})
            print("quote_eta ->", json.loads(ok.content[0].text)["eta_minutes"], "min")
            failures += ok.is_error
            denied = await s.call_tool("orders.create_cart", {"customer_id": "c-42", "items": ["Pesto Pasta"]},
                                       meta={"customer": {"id": "c-42", "diet": "vegetarian", "allergens": ["tree_nuts"], "budget_usd": 25}})
            print("create_cart(Pesto) ->", "isError" if denied.is_error else "ok", "|", (denied.content[0].text if denied.content else "")[:90])
            failures += not denied.is_error
    print("MCP SMOKE", "PASSED" if not failures else f"FAILED ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
