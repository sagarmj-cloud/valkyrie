# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Valkyrie SDK — the only way agents and MCP servers talk to the platform.

    from valkyrie import GatewayClient, mint_dev_token
    from valkyrie.server import make_server

Chooses who passes.
"""

from .client import AsyncGatewayClient, GatewayClient, GatewayUnavailable, InvokeResult, Status, mint_dev_token

__all__ = ["AsyncGatewayClient", "GatewayClient", "GatewayUnavailable", "InvokeResult", "Status", "mint_dev_token"]
__version__ = "0.2.0"
