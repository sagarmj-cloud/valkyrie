# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Server scaffold: build an MCP server that

  * accepts only credentials leased by the gateway for its scope,
  * refuses to start if any of its tools is not in the registry,
  * exposes /healthz,
  * runs over Streamable HTTP.

    from valkyrie.server import make_server, serve
    mcp = make_server("menu", scope="menu:read")

    @mcp.tool()
    def search_menu(query: str = "", vegetarian: bool | None = None) -> dict: ...

    serve(mcp, port=8102)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import anyio
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse


class GatewayLeaseVerifier(TokenVerifier):
    """Accepts lease tokens the gateway's SignedBroker minted for this scope.

    The token is an HS256 JWT {iss, scope, lease_id, iat, exp} signed with the
    key shared between the gateway and first-party servers
    (VALKYRIE_LEASE_KEY). Verification is cryptographic: signature, issuer,
    scope and expiry. A server never accepts a token for another scope, and
    a token outlives its call by at most the manifest TTL.
    """

    def __init__(self, scope: str, key: bytes | None = None, issuer: str = "valkyrie", leeway_s: int = 30):
        self.scope = scope
        self.key = key or os.environ.get("VALKYRIE_LEASE_KEY", "dev-lease-key-change-me").encode()
        self.issuer = issuer
        self.leeway_s = leeway_s

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = verify_hs256(token, self.key)
        if not claims:
            return None
        if claims.get("iss") != self.issuer or claims.get("scope") != self.scope:
            return None
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or time.time() > exp + self.leeway_s:
            return None
        return AccessToken(token=token, client_id="valkyrie-gateway", scopes=[self.scope],
                           expires_at=int(exp), claims={"lease_id": claims.get("lease_id")})


def verify_hs256(token: str, key: bytes) -> dict | None:
    """Minimal HS256 JWT verification (no third-party JWT library on the server)."""
    try:
        h, p, sig = token.split(".")
        want = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
        got = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        if not hmac.compare_digest(want, got):
            return None
        header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
        if header.get("alg") != "HS256":
            return None
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (ValueError, TypeError):
        return None


def registry_dir() -> Path:
    return Path(os.environ.get("VALKYRIE_REGISTRY_DIR", Path(__file__).resolve().parents[3] / "registry" / "manifests"))


def make_server(name: str, *, scope: str, version: str = "0.1.0", instructions: str | None = None) -> MCPServer:
    issuer = os.environ.get("VALKYRIE_ISSUER", "http://127.0.0.1:8080")
    server = MCPServer(
        name=name, version=version, instructions=instructions,
        token_verifier=GatewayLeaseVerifier(scope),
        auth=AuthSettings(issuer_url=issuer, resource_server_url=None, required_scopes=[scope]),
    )

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return server


async def _assert_registered(server: MCPServer) -> None:
    """A server that exposes an unregistered tool must not start."""
    manifests = {p.stem for p in registry_dir().glob("*.yaml")}
    tools = await server.list_tools()
    missing = [t.name for t in tools if t.name not in manifests]
    if missing:
        sys.stderr.write(f"[valkyrie] refusing to start {server.name}: unregistered tools {missing} "
                         f"(add a manifest under {registry_dir()})\n")
        sys.exit(2)


def serve(server: MCPServer, *, port: int, host: str = "127.0.0.1") -> None:
    async def _main() -> None:
        await _assert_registered(server)
        await server.run_streamable_http_async(host=host, port=port, json_response=True, stateless_http=True)

    anyio.run(_main)
