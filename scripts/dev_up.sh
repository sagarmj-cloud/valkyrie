#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
# Start the full local stack: registryd (control plane) → OPA (pulls the signed
# bundle from registryd) → five first-party MCP servers → gateway (loads its
# registry from registryd and polls it). Writes PIDs to .dev/pids.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/.dev"
export PYTHONPATH="$ROOT/sdk/python:${PYTHONPATH:-}"
export VALKYRIE_REGISTRY_DIR="$ROOT/registry/manifests"
export VALKYRIE_REGISTRY_ADMIN_TOKEN="${VALKYRIE_REGISTRY_ADMIN_TOKEN:-dev-admin-token}"
export VALKYRIE_REGISTRY_TOKEN="${VALKYRIE_REGISTRY_TOKEN:-dev-reader-token}"
export VALKYRIE_BUNDLE_KEY="${VALKYRIE_BUNDLE_KEY:-dev-bundle-key-change-me}"
export VALKYRIE_LEASE_KEY="${VALKYRIE_LEASE_KEY:-dev-lease-key-change-me}"
export VALKYRIE_REGISTRYD_URL="http://127.0.0.1:8090"
# Static secrets for third-party tools live only in the gateway's environment
# (credentials.type=static, secret_ref=WEATHER_API_KEY). Dev value for the
# reference weather API; in production this is a mounted secret.
export WEATHER_API_KEY="${WEATHER_API_KEY:-weather-key-123}"
: > "$ROOT/.dev/pids"
OPA_BIN="${OPA_BIN:-$(command -v opa || echo "$ROOT/../bin/opa")}"

# 1. control plane (fresh state unless KEEP_STATE=1)
[ "${KEEP_STATE:-0}" = "1" ] || rm -f "$ROOT/.dev/registryd-state.json"
REGISTRYD_STATE="$ROOT/.dev/registryd-state.json" REGISTRYD_POLICY_DIR="$ROOT/policies" REGISTRYD_LISTEN=127.0.0.1:8090 \
  "$ROOT/bin/registryd" > "$ROOT/.dev/registryd.log" 2>&1 &
echo $! >> "$ROOT/.dev/pids"
for i in $(seq 1 40); do curl -fsS http://127.0.0.1:8090/healthz >/dev/null 2>&1 && break; sleep 0.25; done

# 2. first-party servers
for s in profile menu orders payments delivery; do
  python3 "$ROOT/servers/$s/server.py" > "$ROOT/.dev/$s.log" 2>&1 &
  echo $! >> "$ROOT/.dev/pids"
done
for port in 8101 8102 8103 8104 8105; do
  for i in $(seq 1 120); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
done

# 3. seed the control plane from registry/ (servers, manifests with live contract tests, roles)
export VALKYRIE_REGISTRYD="http://127.0.0.1:8090"
python3 "$ROOT/scripts/seed_registry.py" > "$ROOT/.dev/seed.log" 2>&1 || { cat "$ROOT/.dev/seed.log" >&2; exit 1; }

# 4. OPA, pulling the signed bundle from registryd
"$OPA_BIN" run --server --addr 127.0.0.1:8181 --log-level error --config-file "$ROOT/deploy/opa-config.yaml" > "$ROOT/.dev/opa.log" 2>&1 &
echo $! >> "$ROOT/.dev/pids"

# 5. gateway, registry from registryd
VALKYRIE_REGISTRY="http://127.0.0.1:8090/v1/registry" VALKYRIE_REGISTRY_INTERVAL_S=5 VALKYRIE_AUDIT="$ROOT/.dev/audit.jsonl" \
  "$ROOT/bin/valkyrie" > "$ROOT/.dev/gateway.log" 2>&1 &
echo $! >> "$ROOT/.dev/pids"

for i in $(seq 1 80); do
  if curl -fsS http://127.0.0.1:8080/readyz >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:8181/health?bundles" >/dev/null 2>&1; then
    echo "valkyrie dev stack up: registryd :8090 · opa :8181 (bundle verified) · gateway :8080 · servers :8101-8105"; exit 0
  fi
  sleep 0.25
done
echo "stack failed to start; see .dev/*.log" >&2; tail -5 "$ROOT"/.dev/{registryd,opa,gateway}.log >&2; exit 1
