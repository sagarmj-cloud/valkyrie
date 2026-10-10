# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
import base64
import hashlib
import hmac
import json

import httpx
import pytest

from valkyrie import GatewayClient, Status, mint_dev_token
from valkyrie.client import InvokeResult


def test_mint_dev_token_is_hs256_with_claims():
    tok = mint_dev_token("s", sub="jane", tenant_id="acme", agent_id="a-1", agent_role="ordering")
    h, p, sig = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    assert claims["agent_role"] == "ordering" and claims["tenant_id"] == "acme"
    want = base64.urlsafe_b64encode(hmac.new(b"s", f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == want


def test_invoke_maps_statuses(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["Authorization"].startswith("Bearer ")
        if body["tool"] == "orders.create_cart":
            return httpx.Response(403, json={"status": "denied", "reason": ["allergen_conflict: Pesto Pasta contains tree_nuts"]})
        return httpx.Response(200, json={"status": "ok", "content": {"content": [{"type": "text", "text": '{"eta_minutes": 35}'}]}, "redacted": []})

    c = GatewayClient("http://gw", "tok")
    c._http = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://gw", headers={"Authorization": "Bearer tok"})
    denied = c.invoke("orders.create_cart", {"items": ["Pesto Pasta"]})
    assert denied.status == Status.DENIED and "allergen_conflict" in denied.as_tool_message()
    ok = c.invoke("delivery.quote_eta", {"order_id": "o"})
    assert ok.ok and ok.json()["eta_minutes"] == 35


def test_as_tool_message_shapes():
    r = InvokeResult(status=Status.APPROVAL_REQUIRED)
    assert r.as_tool_message().startswith("APPROVAL REQUIRED")
    r = InvokeResult(status=Status.INVALID, violations=["$.items: expected array"])
    assert "expected array" in r.as_tool_message()


def test_retries_only_with_idempotency_key():
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, json={"error": "upstream"})
        return httpx.Response(200, json={"status": "ok", "content": {}})

    c = GatewayClient("http://gw", "tok", backoff_s=0.0)
    c._http = httpx.Client(transport=httpx.MockTransport(flaky), base_url="http://gw", headers={"Authorization": "Bearer t"})
    assert c.invoke("menu.search_menu", {}, idempotency_key="k").ok and calls["n"] == 3
    calls["n"] = 0
    res = c.invoke("menu.search_menu", {})          # no key: no retry
    assert res.status == Status.UPSTREAM_ERROR and calls["n"] == 1


def test_server_verifies_signed_lease():
    import asyncio
    import time as _t
    from valkyrie.server import GatewayLeaseVerifier

    def jwt(claims, key=b"k"):
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        return f"{h}.{p}.{sig}"

    v = GatewayLeaseVerifier("orders:write", key=b"k")
    good = {"iss": "valkyrie", "scope": "orders:write", "lease_id": "lease-1", "exp": _t.time() + 60}
    assert asyncio.run(v.verify_token(jwt(good))) is not None
    assert asyncio.run(v.verify_token(jwt({**good, "scope": "menu:read"}))) is None       # wrong scope
    assert asyncio.run(v.verify_token(jwt({**good, "exp": _t.time() - 120}))) is None     # expired
    assert asyncio.run(v.verify_token(jwt(good, key=b"other"))) is None                   # wrong key
    assert asyncio.run(v.verify_token("dev.orders:write.deadbeef")) is None               # old prefix tokens rejected
