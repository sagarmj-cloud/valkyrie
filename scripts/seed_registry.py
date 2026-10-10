#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Seed registryd from the repo's declarative registry: servers.yaml, every
manifest under registry/manifests (each goes through the live contract
test), and role bindings from policies/data.json. Idempotent."""
import json
import os
import sys
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("VALKYRIE_REGISTRYD", "http://127.0.0.1:8090")
H = {"Authorization": f"Bearer {os.environ.get('VALKYRIE_REGISTRY_ADMIN_TOKEN', 'dev-admin-token')}", "X-Actor": "seed"}


def main() -> int:
    c = httpx.Client(base_url=BASE, headers=H, timeout=30)
    servers = yaml.safe_load((ROOT / "registry" / "servers.yaml").read_text())["servers"]
    for name, s in servers.items():
        r = c.put(f"/v1/servers/{name}", json={"url": s["url"], "runtime": s.get("runtime", "python")})
        r.raise_for_status()
    for p in sorted((ROOT / "registry" / "manifests").glob("*.yaml")):
        m = yaml.safe_load(p.read_text())
        r = c.put(f"/v1/tools/{m['name']}", json=m)
        if r.status_code != 200:
            print(f"FAILED {p.name}: {r.status_code} {r.text}")
            return 1
        print(f"published {m['name']}@{m['version']} — {'; '.join(r.json()['contract'].get('checked', []))}")
    roles = json.loads((ROOT / "policies" / "data.json").read_text())["roles"]
    for name, role in roles.items():
        tools = role["tools"]
        r = c.put(f"/v1/roles/{name}", json={"tools": tools, "max_tier": role["max_tier"],
                                              "can_delegate": bool(role.get("can_delegate", False))})
        r.raise_for_status()
        print(f"bound role {name}: {len(tools)} tools, max_tier={role['max_tier']}, can_delegate={bool(role.get('can_delegate', False))}")
    rev = c.get("/v1/registry").json()["revision"]
    print(f"registry revision {rev}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
