#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Validate manifests against the manifest schema and emit registry.json
(what the Go gateway loads) plus OPA data for tool tiers. Run by `make registry`
and in CI on every PR that touches registry/."""
import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "registry" / "manifests"
SCHEMA = json.loads((ROOT / "registry" / "schemas" / "manifest.schema.json").read_text())
SERVERS = yaml.safe_load((ROOT / "registry" / "servers.yaml").read_text())["servers"]


def main() -> int:
    tools, errors = [], []
    for path in sorted(MANIFESTS.glob("*.yaml")):
        m = yaml.safe_load(path.read_text())
        try:
            jsonschema.validate(m, SCHEMA)
        except jsonschema.ValidationError as e:
            errors.append(f"{path.name}: {e.message}")
            continue
        if path.stem != m["name"]:
            errors.append(f"{path.name}: file name must equal tool name {m['name']}")
        if m["server"] not in SERVERS:
            errors.append(f"{path.name}: unknown server {m['server']} (see registry/servers.yaml)")
        tools.append(m)
    if errors:
        print("\n".join("ERROR " + e for e in errors), file=sys.stderr)
        return 1
    out = ROOT / "registry" / "registry.json"
    out.write_text(json.dumps({"tools": tools, "servers": SERVERS}, indent=2))
    tiers = {t["name"]: t["risk_tier"] for t in tools}
    (ROOT / "policies" / "tool_tiers.json").write_text(json.dumps({"tool_tiers": tiers}, indent=2))
    print(f"registry: {len(tools)} tools -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
