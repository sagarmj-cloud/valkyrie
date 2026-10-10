# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Gateway client used by agents.

Agents never hold credentials and never call a system directly: the only
network call an agent makes is to the gateway's /v1/tools/invoke, carrying a
signed on-behalf-of token and the context the policy needs (customer,
approval ticket, budget). A deny comes back as a normal result with a reason
the agent can plan around.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


class Status(str, Enum):
    OK = "ok"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    INVALID = "invalid_arguments"
    UNKNOWN_TOOL = "unknown_tool"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_ERROR = "upstream_error"


@dataclass
class InvokeResult:
    status: Status
    reason: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    content: dict[str, Any] = field(default_factory=dict)
    redacted: list[str] = field(default_factory=list)
    decision_id: str = ""
    policy_version: str = ""
    trace_id: str = ""
    http_status: int = 0
    replayed: bool = False

    @property
    def ok(self) -> bool:
        return self.status == Status.OK

    def text(self) -> str:
        """First text content block, or '' — what the LLM sees."""
        for c in self.content.get("content", []) or []:
            if c.get("type") == "text":
                return c.get("text", "")
        return ""

    def json(self) -> Any:
        """structuredContent if present, else the text parsed as JSON, else {}."""
        if self.content.get("structuredContent") is not None:
            return self.content["structuredContent"]
        try:
            return json.loads(self.text())
        except (ValueError, TypeError):
            return {}

    def as_tool_message(self) -> str:
        """The string handed back to the model as the tool result."""
        if self.ok:
            return self.text() or json.dumps(self.json())
        if self.status == Status.DENIED:
            return f"DENIED by policy: {'; '.join(self.reason)}. Choose a different action."
        if self.status == Status.APPROVAL_REQUIRED:
            return "APPROVAL REQUIRED: a human must approve this action before it can run."
        if self.status == Status.INVALID:
            return f"INVALID ARGUMENTS: {'; '.join(self.violations)}"
        if self.status == Status.RATE_LIMITED:
            return f"RATE LIMITED: {'; '.join(self.reason)}. Try again shortly."
        return f"ERROR ({self.status.value}): {'; '.join(self.reason)}"


@dataclass
class DelegationResult:
    """Verdict for a supervisor -> specialist handoff (PEP 2)."""
    allow: bool
    reason: list[str] = field(default_factory=list)
    decision_id: str = ""
    policy_version: str = ""
    trace_id: str = ""
    http_status: int = 0
    token: str = ""          # the specialist's gateway-issued identity (only on allow)
    expires_at: str = ""

    def as_tool_message(self) -> str:
        if self.allow:
            return "delegation allowed"
        return f"DELEGATION DENIED by policy: {'; '.join(self.reason)}. Do the task yourself or choose another agent."


def mint_dev_token(secret: str, *, sub: str, tenant_id: str, agent_id: str, agent_role: str,
                   chain: list[str] | None = None, ttl_s: int = 3600) -> str:
    """HS256 JWT matching gateway/internal/authn. Dev and CI only; production
    tokens come from the IdP and the agent's service identity."""
    def b64(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": sub, "tenant_id": tenant_id, "agent_id": agent_id, "agent_role": agent_role,
                              "chain": chain or [], "exp": int(time.time()) + ttl_s}).encode())
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(sig)}"


class GatewayUnavailable(RuntimeError):
    """The gateway could not be reached after retries."""


class GatewayClient:
    """Synchronous client. Retries connection errors and 502/503/504 with
    exponential backoff, but only when the call carries an idempotency key —
    a retry without one could execute a write twice."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 30.0, trace_id: str | None = None,
                 retries: int = 3, backoff_s: float = 0.2):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.trace_id = trace_id or uuid.uuid4().hex[:16]
        self.retries, self.backoff_s = retries, backoff_s
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout,
                                  headers={"Authorization": f"Bearer {token}", "X-Trace-Id": self.trace_id})

    # -- discovery -------------------------------------------------------
    def tools(self) -> list[dict[str, Any]]:
        """Policy-filtered catalogue: only tools this agent's role may call."""
        r = self._http.get("/v1/tools")
        r.raise_for_status()
        return r.json()["tools"]

    # -- delegation (PEP 2) ---------------------------------------------
    def delegate(self, target: dict[str, Any], task: dict[str, Any], *, budget: dict[str, Any] | None = None) -> DelegationResult:
        """Ask the gateway whether this agent may hand `task` to `target`.

        The gateway takes the caller and its delegation chain from the verified
        token, so neither can be forged here. A deny is a normal result."""
        body: dict[str, Any] = {"target": target, "task": task}
        if budget:
            body["budget"] = budget
        try:
            r = self._http.post("/v1/delegate", json=body)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
            raise GatewayUnavailable(str(e)) from e
        try:
            j = r.json()
        except ValueError:
            return DelegationResult(allow=False, reason=[f"gateway returned {r.status_code}"], http_status=r.status_code)
        return DelegationResult(allow=bool(j.get("allow", False)), reason=list(j.get("reason") or []),
                                decision_id=j.get("decision_id", ""), policy_version=j.get("policy_version", ""),
                                trace_id=j.get("trace_id", ""), http_status=r.status_code,
                                token=j.get("token", ""), expires_at=j.get("expires_at", ""))

    # -- invocation ------------------------------------------------------
    def invoke(self, tool: str, args: dict[str, Any] | None = None, *, customer: dict[str, Any] | None = None,
               approval: dict[str, Any] | None = None, budget: dict[str, Any] | None = None,
               idempotency_key: str | None = None) -> InvokeResult:
        body: dict[str, Any] = {"tool": tool, "args": args or {}}
        if customer:
            body["customer"] = customer
        if approval:
            body["approval"] = approval
        if budget:
            body["budget"] = budget
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        attempts = self.retries if idempotency_key else 0
        last_exc: Exception | None = None
        for attempt in range(attempts + 1):
            try:
                r = self._http.post("/v1/tools/invoke", json=body)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as e:
                last_exc = e
                r = None
            if r is not None and r.status_code not in (502, 503, 504):
                break
            if attempt < attempts:
                time.sleep(self.backoff_s * (2 ** attempt))
        if r is None:
            raise GatewayUnavailable(f"gateway unreachable after {attempts + 1} attempts: {last_exc}")
        data = r.json() if r.content else {}
        if r.status_code == 401:
            raise PermissionError(f"gateway: {data.get('error', 'unauthenticated')}")
        return InvokeResult(
            status=Status(data.get("status", Status.UPSTREAM_ERROR.value)),
            reason=data.get("reason") or [], violations=data.get("violations") or [],
            content=data.get("content") or {}, redacted=data.get("redacted") or [],
            decision_id=data.get("decision_id", ""), policy_version=data.get("policy_version", ""),
            trace_id=data.get("trace_id", ""), http_status=r.status_code, replayed=bool(data.get("replayed")),
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "GatewayClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncGatewayClient:
    """Async twin of GatewayClient for asyncio-based agents."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 30.0, trace_id: str | None = None):
        self.trace_id = trace_id or uuid.uuid4().hex[:16]
        self._http = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout,
                                       headers={"Authorization": f"Bearer {token}", "X-Trace-Id": self.trace_id})

    async def tools(self) -> list[dict[str, Any]]:
        r = await self._http.get("/v1/tools")
        r.raise_for_status()
        return r.json()["tools"]

    async def invoke(self, tool: str, args: dict[str, Any] | None = None, **ctx: Any) -> InvokeResult:
        body: dict[str, Any] = {"tool": tool, "args": args or {}}
        for k in ("customer", "approval", "budget", "idempotency_key"):
            if ctx.get(k):
                body[k] = ctx[k]
        r = await self._http.post("/v1/tools/invoke", json=body)
        data = r.json() if r.content else {}
        if r.status_code == 401:
            raise PermissionError(f"gateway: {data.get('error', 'unauthenticated')}")
        return InvokeResult(status=Status(data.get("status", Status.UPSTREAM_ERROR.value)), reason=data.get("reason") or [],
                            violations=data.get("violations") or [], content=data.get("content") or {},
                            redacted=data.get("redacted") or [], decision_id=data.get("decision_id", ""),
                            policy_version=data.get("policy_version", ""), trace_id=data.get("trace_id", ""),
                            http_status=r.status_code, replayed=bool(data.get("replayed")))

    async def delegate(self, target: dict[str, Any], task: dict[str, Any], *, budget: dict[str, Any] | None = None) -> DelegationResult:
        body: dict[str, Any] = {"target": target, "task": task}
        if budget:
            body["budget"] = budget
        r = await self._http.post("/v1/delegate", json=body)
        j = r.json() if r.content else {}
        return DelegationResult(allow=bool(j.get("allow", False)), reason=list(j.get("reason") or []),
                                decision_id=j.get("decision_id", ""), policy_version=j.get("policy_version", ""),
                                trace_id=j.get("trace_id", ""), http_status=r.status_code,
                                token=j.get("token", ""), expires_at=j.get("expires_at", ""))

    async def aclose(self) -> None:
        await self._http.aclose()
