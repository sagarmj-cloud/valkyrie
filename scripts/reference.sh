#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# Reference implementation: onboard an EXISTING third-party MCP server and a
# plain REST API through the control plane, with the stack already running.
#
#   1. @modelcontextprotocol/server-everything (TypeScript, Streamable HTTP, sessions + SSE) — not ours
#   2. an internal weather REST API with an X-API-Key — no MCP at all
#
# No gateway restart, no OPA restart: registryd publishes, OPA pulls the new
# signed bundle, the gateway polls the new registry snapshot.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT/sdk/python"
export VALKYRIE_REGISTRYD="http://127.0.0.1:8090"
export VALKYRIE_REGISTRY_ADMIN_TOKEN="${VALKYRIE_REGISTRY_ADMIN_TOKEN:-dev-admin-token}"
CTL="$ROOT/bin/valkyriectl"
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

step "start the third-party MCP server (server-everything over Streamable HTTP) and the weather REST API"
EVERY="$ROOT/reference/node_modules/@modelcontextprotocol/server-everything/dist/index.js"
[ -f "$EVERY" ] || (cd "$ROOT/reference" && npm install --silent @modelcontextprotocol/server-everything)
PORT=3101 node "$EVERY" streamableHttp > "$ROOT/.dev/everything.log" 2>&1 &
echo $! >> "$ROOT/.dev/pids"
python3 "$ROOT/reference/weather-api/server.py" > "$ROOT/.dev/weather.log" 2>&1 &
echo $! >> "$ROOT/.dev/pids"
for i in $(seq 1 40); do curl -fsS http://127.0.0.1:8201/healthz >/dev/null 2>&1 && break; sleep 0.25; done
sleep 1

step "import-mcp: discover server-everything's tools and draft one manifest per tool"
rm -rf "$ROOT/.dev/imported"
"$CTL" import-mcp everything http://127.0.0.1:3101/mcp --tier 0 --owner team-platform --scope everything:read --out "$ROOT/.dev/imported" --runtime node

step "a human reviews the drafts: get-sum and echo stay tier 0; the toggles and the long-running trigger become tier 2"
python3 - "$ROOT/.dev/imported" <<'PY'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
for p in d.glob("everything.*.json"):
    m = json.loads(p.read_text())
    if m["upstream_name"] in ("trigger-long-running-operation", "toggle-simulated-logging", "toggle-subscriber-updates"):
        m["risk_tier"] = 2
        m["idempotent"] = False
    p.write_text(json.dumps(m, indent=2))
print("reviewed", len(list(d.glob('*.json'))), "manifests")
PY

step "publish the reviewed manifests (each one is contract-tested live against the server)"
"$CTL" publish "$ROOT"/.dev/imported/everything.get_sum.json "$ROOT"/.dev/imported/everything.echo.json "$ROOT"/.dev/imported/everything.get_tiny_image.json

step "publish the REST tool: an HTTP-adapter manifest, no MCP server involved"
"$CTL" server add weather http://127.0.0.1:8201 --runtime external --owner team-platform
"$CTL" publish "$ROOT/reference/weather.forecast.json"

step "bind a new 'analyst' role to the imported tools + weather, and give the concierge weather too"
"$CTL" role bind analyst --max-tier 1 everything.get_sum everything.echo weather.forecast
"$CTL" role bind concierge --max-tier 1 profile.get_preferences weather.forecast

step "wait for OPA to pull the new signed bundle and the gateway to poll the new snapshot (no restarts)"
REV=$(curl -s -H "Authorization: Bearer dev-reader-token" http://127.0.0.1:8090/v1/registry | python3 -c "import sys,json;print(json.load(sys.stdin)['revision'])")
for i in $(seq 1 60); do
  O=$(curl -s http://127.0.0.1:8181/v1/data/registry_revision | python3 -c "import sys,json;print(json.load(sys.stdin).get('result',0))")
  G=$(curl -s http://127.0.0.1:8080/metrics >/dev/null; curl -s -H "Authorization: Bearer $(python3 -c "from valkyrie import mint_dev_token as m;print(m('dev-secret-change-me',sub='ref',tenant_id='acme',agent_id='ref',agent_role='analyst'))")" http://127.0.0.1:8080/v1/tools | python3 -c "import sys,json;print(len(json.load(sys.stdin)['tools']))")
  [ "$O" = "$REV" ] && [ "$G" -ge 3 ] && break
  sleep 1
done
echo "registry revision $REV · OPA has revision $O · analyst sees $G tools"

step "call the third-party tool and the REST tool through the gateway, as the analyst"
"$ROOT/scripts/reference_calls.py"

step "the change log — who published what, when"
"$CTL" changes | head -n 12
"$CTL" tools
