#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Exercise the onboarded tools through the gateway and assert the outcomes."""
import os
import sys

from valkyrie import GatewayClient, Status, mint_dev_token

SECRET = os.environ.get("VALKYRIE_AUTH_SECRET", "dev-secret-change-me")
GW = os.environ.get("VALKYRIE_URL", "http://127.0.0.1:8080")


def client(role: str) -> GatewayClient:
    return GatewayClient(GW, mint_dev_token(SECRET, sub="ref@example.com", tenant_id="acme", agent_id=f"ref-{role}", agent_role=role))


def show(label: str, r) -> None:
    mark = {"ok": "✅", "denied": "⛔", "rate_limited": "⏳", "invalid_arguments": "🚫"}.get(r.status.value, "⚠️ ")
    extra = f"redacted {r.redacted}" if r.redacted else ("; ".join(r.reason or r.violations))
    print(f"  {mark} {label:<46} {r.status.value:<12} {r.text()[:60] if r.ok else extra}")


def main() -> int:
    fails = 0
    a = client("analyst")
    r = a.invoke("everything.get_sum", {"a": 19, "b": 23}, idempotency_key="ref-add-1")
    show("everything.get_sum(19, 23) [third-party MCP, SSE]", r); fails += not (r.ok and "42" in r.text())
    r = a.invoke("everything.echo", {"message": "hello through valkyrie"})
    show("everything.echo(...)    [third-party MCP]", r); fails += not r.ok
    r = a.invoke("weather.forecast", {"city": "Pleasanton", "units": "f"})
    show("weather.forecast(Pleasanton, f)  [REST adapter]", r); fails += not (r.ok and "72" in r.text())
    r = a.invoke("weather.forecast", {"city": "Pleasanton", "units": "kelvin"})
    show("weather.forecast(units=kelvin)  [schema reject]", r); fails += r.status != Status.INVALID
    r = a.invoke("everything.get_tiny_image", {})
    show("everything.get_tiny_image  [not bound to role]", r); fails += r.status != Status.DENIED
    r = client("menu").invoke("everything.get_sum", {"a": 1, "b": 2})
    show("menu role → everything.get_sum  [role boundary]", r); fails += r.status != Status.DENIED
    c = client("concierge")
    r = c.invoke("weather.forecast", {"city": "Seattle"})
    show("concierge → weather.forecast  [newly bound]", r); fails += not r.ok
    r2 = a.invoke("everything.get_sum", {"a": 19, "b": 23}, idempotency_key="ref-add-1")
    show("everything.get_sum replay [idempotency key]", r2); fails += not r2.replayed
    print("\nREFERENCE", "PASSED" if not fails else f"FAILED ({fails})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
