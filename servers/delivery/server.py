# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""delivery — ETA quotes (tier 0, internal). Python adapter."""
from datetime import datetime, timedelta, timezone

from valkyrie.server import make_server, serve

mcp = make_server("delivery", scope="delivery:read", instructions="Delivery time quotes.")


@mcp.tool(name="delivery.quote_eta")
def quote_eta(order_id: str) -> dict:
    """Quote the estimated delivery time for an order."""
    eta = datetime.now(timezone.utc) + timedelta(minutes=35)
    return {"order_id": order_id, "eta": eta.isoformat(timespec="minutes"), "eta_minutes": 35}


if __name__ == "__main__":
    serve(mcp, port=8105)
