# Valkyrie Developer Guide

*Chooses who passes.*

Valkyrie is a homegrown MCP / tool-calling platform for multi-agent AI systems. The name is the job: a Valkyrie chooses who passes. Agents propose tool calls; Open Policy Agent decides whether each one is allowed; the Valkyrie gateway executes the allowed ones with a short-lived credential and records the decision. Agents never hold credentials and never reach a system directly.

This guide covers how the pieces fit, how to run them, how to add a tool, a policy, a server and an agent, and what to know before going to production.

---

## 1. Architecture in one page

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/pipeline.png">
    <img src="img/pipeline.png" alt="How a tool call moves through Valkyrie: registryd publishes the registry snapshot (polled every 30 s) and the signed bundle (polled every 5–15 s, signature verified); callers invoke the gateway, which authenticates, resolves and rate-limits, validates, asks the OPA sidecar for a verdict, leases a credential, executes against an MCP server or HTTP adapter, then redacts, audits and revokes; targets are first-party MCP servers, third-party MCP servers and REST APIs in front of the target systems." width="1100">
  </picture>
</p>

| Plane | Directory | Language | What lives there |
| --- | --- | --- | --- |
| Control | `controlplane/` (registryd, valkyriectl), `registry/` | Go, stdlib only | Publishes manifests with a live contract test, binds roles, serves the registry snapshot to gateways and the signed OPA bundle to sidecars, keeps a change log |
| Policy | `policies/` | Rego | `tool_authz` (PEP 3), `delegation` (PEP 2), `data_egress` (PEP 4), policy data, tests |
| Data | `gateway/` | Go, stdlib only | The seven-step pipeline, both faces (`/v1/tools/invoke`, `/mcp`), rate limits, idempotency, metrics, audit |
| Runtime | `servers/`, `sdk/python/valkyrie/server.py` | Python, `mcp` 2.x | One MCP server per system, generated from the scaffold |
| Agents | `agents/`, `sdk/python/valkyrie/client.py` | Python, LangGraph | Supervisor + specialists; the gateway client |
| Deploy | `deploy/` | compose, Kubernetes | Gateway + OPA sidecar pod, per-server Deployments, network policy |

Why the gateway is standard-library Go, the servers Python, and OPA a sidecar is explained in the two accompanying articles; the short version is in §10.

---

## 2. Quick start

Prerequisites: Go 1.24+, Python 3.10+, the `opa` binary on `PATH` ([install](https://www.openpolicyagent.org/docs/latest/#running-opa)), `make`, `curl`.

```bash
git clone <repo> valkyrie && cd valkyrie
make deps          # pip install -r requirements.txt
make test          # manifests → registry.json, opa test + regression corpus, go test -race (gateway + control plane), pytest
make demo          # starts registryd + OPA + 5 servers + gateway, runs the pizza scenario, stops everything
make smoke         # exercises the /mcp face with the official MCP Python client
make reference     # onboards a third-party MCP server and a REST API through the control plane, calls both
make e2e           # all three against one running stack (what CI runs)
```

`make up` starts the stack in this order: **registryd** (control plane) → five first-party **servers** → `scripts/seed_registry.py` publishes every manifest under `registry/manifests` through registryd (each passes a live contract test) and binds roles → **OPA** starts and pulls the signed bundle from registryd → the **gateway** starts with `VALKYRIE_REGISTRY=http://127.0.0.1:8090/v1/registry` and polls it every 5 s. Nothing is read from `registry.json` any more; the file is still produced by `make registry` for CI validation and for the `scripts/build_registry.py` compatibility path.

`make demo` output ends with:

```
  AGENT       TOOL                      STATUS             DETAIL
  concierge   profile.get_preferences   ✅ ok               redacted ['address_line_2', 'phone', 'email']
  menu        menu.search_menu          ✅ ok
  ordering    orders.create_cart        ⛔ denied           allergen_conflict: Pesto Pasta contains tree_nuts
  ordering    orders.create_cart        ✅ ok
  ordering    orders.place_order        ✅ ok
  ordering    payments.charge           ✅ ok
  ordering    delivery.quote_eta        ✅ ok

🤖  Agent: “Done — Margherita Pizza from Luigi's, $20.70 including tip, arriving in about 35 minutes.
            Order ord-4824. I skipped Pesto Pasta (allergen conflict).”
DEMO PASSED
```

To keep the stack running while you work: `make up`, then `make down`. Logs are in `.dev/*.log`; the audit log is `.dev/audit.jsonl`; Prometheus metrics are at `localhost:8080/metrics`.

### Calling the gateway by hand

```bash
export PYTHONPATH=sdk/python
TOKEN=$(python3 -c "from valkyrie import mint_dev_token as m; print(m('dev-secret-change-me', sub='me', tenant_id='acme', agent_id='cli', agent_role='ordering'))")

# what can this role see?
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/v1/tools | python3 -m json.tool | grep '"name"'

# a call the policy will refuse
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/v1/tools/invoke -d '{
  "tool": "orders.create_cart",
  "args": {"customer_id": "c-42", "items": ["Pesto Pasta"]},
  "customer": {"id": "c-42", "diet": "vegetarian", "allergens": ["tree_nuts"], "budget_usd": 25}
}'
# → 403 {"status":"denied","reason":["allergen_conflict: Pesto Pasta contains tree_nuts"],"decision_id":"…","policy_version":"v2026.10.1"}
```

---

## 3. Repository layout

```
valkyrie/
├── registry/
│   ├── manifests/*.yaml          one file per tool; file name == tool name
│   ├── schemas/manifest.schema.json
│   └── servers.yaml              server name → URL, runtime
├── policies/
│   ├── tool_authz.rego           PEP 3 — the one every call hits
│   ├── delegation.rego           PEP 2 — supervisor → specialist
│   ├── data_egress.rego          PEP 4 — result classification
│   ├── data.json                 roles, tiers, menu allergens, limits, policy_version
│   └── tests/*_test.rego
├── controlplane/                 Go module `valkyrie/controlplane`, no external deps
│   ├── cmd/registryd/            the control-plane service
│   ├── cmd/valkyriectl/          operator CLI (publish, import-mcp, role bind, tools, changes)
│   └── internal/
│       ├── store/      revisioned state: tools, servers, roles, change log (atomic file; Postgres-shaped interface)
│       ├── api/        REST surface; validation; ETag snapshot; signed bundle endpoint
│       ├── bundle/     builds the OPA bundle: policies + data.json merged with roles/tiers, HS256-signed
│       ├── contract/   publish-time contract test against the live server
│       └── mcpdiscover/ minimal MCP client (initialize, tools/list) for contract tests and import-mcp
├── policy-corpus/                recorded policy inputs + expected verdicts, replayed by make policy-test
├── reference/                    the reference onboarding: server-everything (third-party MCP) + a REST weather API
├── gateway/                      Go module `valkyrie/gateway`, no external deps
│   ├── cmd/valkyrie/main.go
│   └── internal/
│       ├── api/        two faces: REST invoke + MCP Streamable HTTP
│       ├── pipeline/   the seven steps (transport-agnostic)
│       ├── authn/      OIDC/JWKS RS256 verifier (prod) · HS256 verifier (dev) · Chain
│       ├── registry/   manifests in memory; Loader polls a file or registryd with ETag and hot-swaps
│       ├── schema/     JSON Schema subset validator (reject, never coerce)
│       ├── policy/     OPA client, Decision object, fail-closed
│       ├── credentials/ SignedBroker (HS256 leases) · VaultBroker (Vault HTTP API) · StaticBroker · NoneBroker · Router
│       ├── store/      shared state: bounded TTL memory store · Redis (RESP2 client, stdlib)
│       ├── ratelimit/  fixed-window per tenant × tool from the manifest's rate_per_minute
│       ├── metrics/    Prometheus text exposition: calls, denies by reason, latency histogram, circuits
│       ├── upstream/   MCP client (sessions, SSE, semaphore, circuit breaker, session recovery) · HTTP adapter for REST tools
│       ├── audit/      one JSONL event per call, args hashed
│       └── mcpjson/    JSON-RPC + MCP message types
├── sdk/python/valkyrie/
│   ├── client.py                 GatewayClient, InvokeResult, mint_dev_token
│   └── server.py                 make_server(), serve(): scope-checked, registry-checked
├── servers/{profile,menu,orders,payments,delivery}/server.py
├── agents/pizza/{graph.py,run.py}  LangGraph supervisor + specialists
├── deploy/{compose,k8s,opa-config.yaml}
├── scripts/{build_registry.py,dev_up.sh,dev_down.sh,smoke_mcp.py}
└── Makefile · requirements.txt · .github/workflows/ci.yml
```

---

## 4. The control plane: registryd and valkyriectl

registryd is the source of truth for what can be called. The gateway and OPA never read files; they poll registryd.

| Endpoint | Who calls it | What it does |
| --- | --- | --- |
| `PUT /v1/servers/{name}` | operators (`valkyriectl server add`) | register an MCP server or a logical name for an adapter |
| `PUT /v1/tools/{name}` | operators / CI (`valkyriectl publish`) | validate the manifest, run the **live contract test**, store a new revision |
| `DELETE /v1/tools/{name}` | operators | deprecate: removed from the snapshot, kept in history |
| `PUT /v1/roles/{name}` | operators (`valkyriectl role bind`) | bind tools to a role with a tier ceiling and, with `--can-delegate`, the right to hand tasks to other agents; refuses unknown tools |
| `GET /v1/registry` | **gateways**, every 30 s with `If-None-Match` | the active snapshot: tools + servers, `ETag: "r<revision>"` |
| `GET /v1/bundle.tar.gz` | **OPA sidecars**, every 5–15 s | the signed policy bundle: `.manifest`, `.signatures.json`, `data.json`, `*.rego` |
| `GET /v1/tools`, `/v1/changes` | humans, dashboards | listing and the change log (who, what, when, revision) |

Writes require `VALKYRIE_REGISTRY_ADMIN_TOKEN`; reads require `VALKYRIE_REGISTRY_TOKEN` when set. The `X-Actor` header is recorded in the change log (the CLI sends `$USER`). In production both tokens become OIDC identities with roles; the handlers do not change.

### What happens on publish

1. **Validate** the manifest shape (name grammar, semver, tier 0–3, classification, credential type, limits, tier-3-needs-approval).
2. **Contract-test** it against the live server: `initialize` + `tools/list` with the credential the gateway would use (a short signed lease for first-party servers, the static secret for third-party ones), check the tool exists (`upstream_name` or `name`), check every argument the server requires is in the manifest's `input_schema` and every argument the manifest declares exists on the server. For HTTP adapters: the URL is absolute and every `{placeholder}` is a schema property. `?skip_contract=1` exists for servers that are offline at publish time; CI never uses it.
3. **Version-gate**: the new version must be ≥ the current one; `If-Match-Version` gives optimistic concurrency.
4. **Commit** a new revision and append to the change log. The snapshot ETag and the bundle cache invalidate; gateways and OPA pick the change up on their next poll — no restarts.

### The signed bundle

The bundle's `data.json` is the checked-in `policies/data.json` with `roles` and `tool_tiers` replaced by the control plane's store, plus `registry_revision`. It is signed as a JWT over the file digests (HS256 with `VALKYRIE_BUNDLE_KEY`, key id `valkyrie-ci`, scope `valkyrie`); OPA verifies it before activation (`deploy/opa-config.yaml`) and keeps the last good bundle if verification fails. Switching to RS256 is a config change on both sides. Two details that bit during development and are now encoded in the builder: OPA canonicalises JSON before hashing (compact, sorted keys, number literals preserved, no HTML escaping), and the `scope` claim must match the config.

### Onboarding an existing MCP server

`valkyriectl import-mcp` is the on-ramp for servers nobody on the platform team wrote:

```bash
valkyriectl import-mcp everything http://everything.internal:3101/mcp \
    --tier 0 --owner team-platform --scope everything:read --runtime node \
    --auth-env EVERYTHING_API_KEY --auth-header X-API-Key   # omit both for an open server
```

It registers the server, calls `tools/list`, and writes one manifest per tool as `<server>.<tool>` with the server's own input schema and `upstream_name` set to the original name (namespacing prevents collisions between servers). The flags are the facts a server cannot tell you: who owns it, how risky it is, what credential to use. Review the drafts — tiers above all — then `valkyriectl publish drafts/*.json` and `valkyriectl role bind`. `make reference` runs exactly this against `@modelcontextprotocol/server-everything`.

### Onboarding a plain REST API

No MCP server is needed. A manifest with an `adapter` block makes the gateway call the endpoint directly, with the credential attached per `credentials.header`:

```json
"credentials": { "type": "static", "secret_ref": "WEATHER_API_KEY", "scope": "weather:read", "header": "X-API-Key", "ttl_seconds": 60 },
"adapter":     { "type": "http", "method": "GET", "url": "http://weather.internal/v1/forecast/{city}", "query": ["units"] }
```

`{city}` is substituted from the arguments (path-escaped), `units` becomes a query parameter, remaining arguments go in a JSON body when `"body": true`. Redirects are never followed, and in production `VALKYRIE_ADAPTER_ALLOW_HOSTS` must list the hosts the adapter may reach. Redaction and size caps apply to adapter results exactly as to MCP results. See `reference/weather.forecast.json`.

---

## 5. Adding a tool

A tool is a product: it has an owner, a contract, a risk tier and tests. Adding one is a pull request that touches three places.

**1. Write the manifest** `registry/manifests/<server>.<tool>.yaml`:

```yaml
name: orders.cancel_order          # <server>.<tool>; file name must match
owner: team-commerce
server: orders
version: 1.0.0
description: Cancel an order that has not yet been dispatched.
risk_tier: 3                        # 0 read · 1 read-PII · 2 write · 3 destructive / financial
data_classification: confidential
input_schema:
  type: object
  properties:
    order_id: { type: string, minLength: 1 }
    reason:   { type: string, maxLength: 200 }
  required: [order_id]
  additionalProperties: false       # always; unknown arguments are rejected at the gateway
credentials: { vault_role: orders-writer, scope: "orders:write", ttl_seconds: 120 }
limits: { timeout_ms: 5000, rate_per_minute: 30, max_result_kb: 16 }
idempotent: true
approval: { required_above_usd: 0 } # tier 3 always needs a ticket (see tool_authz.rego)
```

`make registry` validates it against `registry/schemas/manifest.schema.json` and refuses unknown servers, bad names and missing fields.

**2. Publish and bind it** through the control plane (locally `make up` does this for everything under `registry/manifests`; in production CI does it on merge):

```bash
valkyriectl publish registry/manifests/orders.cancel_order.yaml     # live contract test runs here
valkyriectl role bind ordering --max-tier 3 orders.create_cart orders.place_order orders.cancel_order payments.charge delivery.quote_eta
valkyriectl role bind concierge --max-tier 1 --can-delegate profile.get_preferences   # supervisors need the delegation grant
```

A tool that is in no role's list is invisible to every agent: `tools/list` will not return it and a call is refused with `tool_not_bound_to_role`. `policies/data.json` still holds the dev defaults that `scripts/seed_registry.py` loads; the bundle served to OPA takes roles from registryd.

**3. Implement it** in the server, with the same name:

```python
@mcp.tool(name="orders.cancel_order")
def cancel_order(order_id: str, reason: str | None = None) -> dict:
    """Cancel an order that has not yet been dispatched."""
    ...
```

The scaffold checks at startup that every tool the server exposes has a manifest, and refuses to start otherwise (`[valkyrie] refusing to start orders: unregistered tools [...]`).

**4. Add a policy test** if the tool has its own rule (see §6), run `make test`, open the PR. CI runs the manifest build, `opa test` with a 90 percent coverage gate, `go test -race`, pytest and the end-to-end demo.

---

## 6. Writing policy

Policies live in `policies/` and use OPA's v1 syntax (`import rego.v1`). The gateway asks for one document, `valkyrie/tool_authz/decision` — the **verdict** — and enforces whatever comes back:

```json
{ "allow": false,
  "deny_reason": ["allergen_conflict: Pesto Pasta contains tree_nuts"],
  "obligations": { "redact_fields": ["phone", "email"], "max_rows": 100, "ttl_seconds": 300 },
  "policy_version": "v2026.10.1" }
```

### The input the gateway sends

```json
{
  "agent":     { "id": "ordering-01", "role": "ordering" },
  "principal": { "sub": "jane.doe", "tenant_id": "acme" },
  "tool":      { "name": "orders.create_cart", "risk_tier": 2, "data_classification": "confidential",
                 "args": { "customer_id": "c-42", "items": ["Pesto Pasta"] } },
  "chain":     ["concierge-01", "menu-01"],
  "customer":  { "id": "c-42", "diet": "vegetarian", "allergens": ["tree_nuts"], "budget_usd": 25 },
  "approval":  { "ticket_id": "APR-7781" },
  "budget":    { "usd_used": 0.4, "usd_limit": 5 }
}
```

`customer`, `approval` and `budget` are optional context the agent attaches to the call (the REST face takes them as top-level fields; the MCP face takes them in `params._meta`). Rules that need them should fail closed when they are absent, as `missing_customer_context` does.

### Rules of the road

- **`default allow := false`.** Always. A rule that does not fire is a deny.
- **Put facts in data, logic in Rego.** Roles, tiers, allergens and limits are in `data.json` (and, in production, generated from the registry into a bundle). A tool owner changes a tier through a manifest PR; nobody edits Rego for that.
- **One reason per rule.** `deny_reason contains "<snake_case_reason>"` or `sprintf("<reason>: %s", [...])`. The reason is what the agent reads to re-plan and what the audit log stores, so make it specific.
- **Obligations are instructions to the gateway**, not to the server. The gateway implements `redact_fields` and `max_rows`; add a new obligation only together with its enforcement in `pipeline.applyObligations`.
- **Test every rule both ways.** `policies/tests/` has one test per allow path and one per deny reason. Run `opa test policies -v`.

### Adding a rule

```rego
# Orders can only be cancelled by the ordering role within 10 minutes of placement.
deny_reason contains "cancel_window_closed" if {
    input.tool.name == "orders.cancel_order"
    time.now_ns() - input.order.placed_at_ns > 10 * 60 * 1000000000
}
```

```rego
test_cancel_window if {
    inp := object.union(base, {"tool": {"name": "orders.cancel_order", "risk_tier": 3, "data_classification": "confidential",
        "args": {"order_id": "o-1"}}, "order": {"placed_at_ns": time.now_ns() - 3600 * 1000000000}})
    "cancel_window_closed" in tool_authz.deny_reason with input as inp
}
```

### Promotion

Policies ship as signed bundles. The CI job runs `opa fmt --fail`, `opa check --strict`, `opa test --coverage` (gate: 90 percent) and then builds `policies/` into a bundle signed with cosign. Promote the bundle dev → staging → canary tenants → all; `data.policy_version` is bumped on every release and appears in every audit event.

---

## 7. Writing an MCP server

Servers are thin. The scaffold gives you auth, health and the registry check; you write tools.

```python
# servers/inventory/server.py
from valkyrie.server import make_server, serve

mcp = make_server("inventory", scope="inventory:read", instructions="Stock levels per store.")

@mcp.tool(name="inventory.get_stock")
def get_stock(sku: str, store_id: str) -> dict:
    """Return on-hand quantity for a SKU at a store."""
    return {"sku": sku, "store_id": store_id, "on_hand": 12}

if __name__ == "__main__":
    serve(mcp, port=8106)
```

Then: add `inventory` to `registry/servers.yaml`, write `registry/manifests/inventory.get_stock.yaml`, bind the tool to a role, add the server to `scripts/dev_up.sh` and `deploy/`.

What the scaffold does for you:

- **Credential check.** The server accepts only lease tokens the gateway's `SignedBroker` minted for its scope: an HS256 JWT `{iss, scope, lease_id, exp, sub, tenant_id}` verified with `VALKYRIE_LEASE_KEY` — signature, issuer, scope and expiry all checked (`GatewayLeaseVerifier`). A token for `orders:write` cannot call `inventory.get_stock`, and a leaked token dies with its TTL. Rotate the key by running both keys for one TTL window.
- **Registry check.** `serve()` lists the server's tools and exits with code 2 if any is unregistered.
- **Transport.** Streamable HTTP, stateless, JSON responses (`json_response=True`) because the gateway handles streaming to the client. Turn on SSE responses only for long-running tools that emit progress.
- **Health.** `GET /healthz` for readiness probes.

Conventions:

- Tool names are `<server>.<tool>`, and the function's type hints *are* the schema. Keep the manifest's `input_schema` in sync (CI compares them in a future iteration; today it is a review item).
- Raise `ValueError` for bad input; the SDK turns it into an `isError` result the gateway passes through.
- Never read secrets from the environment. The only credential you see is the one on the request.
- Keep results small. The manifest's `max_result_kb` is enforced at the gateway; a server that returns 40 MB wastes everyone's time.

When to write a server in Go instead: when it is called on every agent turn, fans out to many backends, or returns large results it has to parse. The gateway does not care which language a server is written in.

---

## 8. Writing an agent

Agents use `GatewayClient`. That is the whole integration surface.

```python
from valkyrie import GatewayClient, Status, mint_dev_token

token = mint_dev_token(SECRET, sub="jane.doe", tenant_id="acme", agent_id="ordering-01", agent_role="ordering")
gw = GatewayClient("http://127.0.0.1:8080", token)

gw.tools()                                   # policy-filtered catalogue for this role
res = gw.invoke("orders.create_cart", {"customer_id": "c-42", "items": ["Pesto Pasta"]},
                customer={"id": "c-42", "diet": "vegetarian", "allergens": ["tree_nuts"], "budget_usd": 25},
                idempotency_key="run-1:create_cart:1")
res.status          # Status.DENIED
res.reason          # ["allergen_conflict: Pesto Pasta contains tree_nuts"]
res.as_tool_message()   # "DENIED by policy: … Choose a different action."  ← hand this to the model
```

### The LangGraph pattern

`agents/pizza/graph.py` is the reference. The shape to copy:

1. **One identity per role.** Each node mints (in production: obtains) a token with its own `agent_role`, so the policy sees exactly who is calling. Do not share one client across roles.
1. **Ask before you hand off, and use the token you get back.** Before a supervisor delegates, it calls `client.delegate(target, task, budget=...)` (`POST /v1/delegate`, PEP 2). The gateway evaluates `valkyrie/delegation/decision` with the caller and the delegation chain taken from the verified token, never from the request, and audits the verdict as `delegate:<target>`. Only roles granted `can_delegate` in the registry (`valkyriectl role bind <role> --can-delegate ...`) may delegate, and the target role must exist. On allow the gateway **issues the specialist's token** (`result.token`): the parent's end user and tenant, the target's id and role, the chain extended by the parent, signed with `VALKYRIE_DELEGATION_KEY`. The specialist calls the gateway with that token; it never mints its own, so an unapproved handoff has no identity to act with. Every tool call is additionally checked for chain integrity in `tool_authz` (`delegation_loop`, `delegation_too_deep`).
2. **Context travels with the call.** The slice of the profile the policy needs (`diet`, `allergens`, `budget_usd`) is stored on the state as `customer_ctx` and attached to every `invoke`. Declare it in the `TypedDict` — LangGraph drops undeclared keys silently, which is exactly the bug the `missing_customer_context` rule now catches.
3. **Deny is a branch, not an exception.** Loop over candidates; on `Status.DENIED` record the reason and try the next one. Never catch and retry the same call.
4. **Approval is an interrupt.** On `Status.APPROVAL_REQUIRED`, store `pending_approval` and route to a node that calls `interrupt(...)`. The checkpointer persists the run; `graph.invoke(Command(resume={"ticket_id": "APR-…"}), cfg)` continues it, and the retry carries `approval={"ticket_id": …}` so OPA's `valid_ticket` passes.
5. **Idempotency keys** are `run_id:tool:hash(args)`; the gateway replays a cached result for the same key and never executes an idempotent tool twice.

Running with a real model: the demo uses a deterministic planner so CI needs no API key. To let an LLM drive, bind the gateway catalogue as LangChain tools and keep the same tool node — the gateway contract (status + reason) is the only thing the model needs.

---

## 9. The gateway internals

### Request lifecycle

`internal/pipeline/pipeline.go: Invoke` is the whole story; each step is a few lines and the comments say why. Things worth knowing:

- **Fail closed everywhere.** OPA unreachable → `denied` with reason `policy_unavailable`. Registry missing a tool → `unknown_tool`. Schema violation → `invalid_arguments` before OPA is even asked.
- **Deadline from the manifest.** `context.WithTimeout(ctx, limits.timeout_ms)` wraps the lease and the upstream call; a client disconnect cancels both.
- **Lease lifetime = call lifetime.** `defer Broker.Revoke(...)` runs on every exit path, including timeouts (there is a test for this).
- **Redaction** rewrites `structuredContent` and any text block that parses as JSON, recursively, for the fields OPA named. The audit event lists what was redacted.
- **Idempotency cache** is in-process in dev. In production it is Redis keyed by `tenant|key` with the manifest TTL.

### Two faces

| Face | Path | Client | Context |
| --- | --- | --- | --- |
| REST | `POST /v1/tools/invoke`, `GET /v1/tools` | `GatewayClient` | top-level `customer`, `approval`, `budget` |
| MCP | `POST /mcp` (Streamable HTTP, JSON responses) | Claude Code, Cursor, any MCP client | `params._meta.{customer,approval,budget}` |

On the MCP face a policy deny is a tool result with `isError: true` and the reason as text, not a JSON-RPC error — the model must see it. Only an unknown tool is a protocol error.

### Upstream client

`internal/upstream/mcp_client.go` speaks MCP Streamable HTTP to servers: `initialize` once per server (session id cached), `tools/call` with the leased bearer, JSON or SSE responses. A semaphore bounds in-flight calls per server (`VALKYRIE_MAX_INFLIGHT`); after `MaxFailures` consecutive errors the circuit opens for `Cooldown`. Both are unit-tested.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `VALKYRIE_LISTEN` | `:8080` | bind address |
| `VALKYRIE_REGISTRY` | `registry.json` | path to the built registry |
| `VALKYRIE_OPA_URL` | `http://127.0.0.1:8181` | OPA sidecar |
| `VALKYRIE_AUTH_SECRET` | `dev-secret-change-me` | HS256 secret for the dev verifier |
| `VALKYRIE_AUDIT` | `-` (stdout) | audit JSONL path |
| `VALKYRIE_MAX_INFLIGHT` | `64` | per-server concurrency |

### Observability

Every call emits one audit event (`internal/audit`) with `trace_id`, `decision_id`, `policy_version`, `lease_id`, `args_hash`, `outcome`, `latency_ms`. OPA's own decision log (enabled in `deploy/opa-config.yaml`) carries the full input; join the two on `decision_id`. Dashboards to build first: deny rate by reason, p99 by tool, approval-queue age, circuit-open events per server.

---

## 10. Production checklist

What the dev stack stubs, and what replaces it.

| Concern | Dev | Production |
| --- | --- | --- |
| Caller identity | HS256 JWT from `mint_dev_token` | **Built:** `authn.JWKSVerifier` (RS256, issuer/audience/exp, JWKS cache with rate-limited refresh). Set `VALKYRIE_OIDC_ISSUER`, `VALKYRIE_OIDC_AUDIENCE`, `VALKYRIE_OIDC_JWKS_URL`; the agent service obtains an on-behalf-of token from the IdP (Okta, Entra, Auth0: OAuth 2.0 token exchange, RFC 8693) carrying `sub`, `tenant_id`, `agent_id`, `agent_role` and `chain`. **`VALKYRIE_ENV=prod` refuses to start without a JWKS URL and never loads the HMAC verifier**: subject, tenant and chain are only as trustworthy as their issuer. mTLS peer identity is terminated at the ingress today. |
| Delegated identities | `dev-delegation-key-change-me` | **Built:** `authn.Issuer` signs specialist tokens after an allowed handoff (`iss=valkyrie-gateway`, own trust domain: the OIDC and HMAC verifiers reject them and vice versa). Set a 32-byte random `VALKYRIE_DELEGATION_KEY`; `VALKYRIE_DELEGATION_TTL_S` (default 900) bounds a specialist's lifetime. To have the IdP issue per-hop tokens instead (RFC 8693 token exchange), replace `Issuer.Issue` and keep the verifier chain. |
| Credentials | `SignedBroker` with the dev lease key | **Built:** `SignedBroker` with a 32-byte random `VALKYRIE_LEASE_KEY` for first-party servers; `VaultBroker` (`VALKYRIE_VAULT_ADDR/TOKEN/MOUNT`) for dynamic secrets; `StaticBroker` for third-party API keys mounted into the gateway only. Signed leases carry `sub` and `tenant_id`, so a first-party server can authorize and audit at user level (`GatewayLeaseVerifier` exposes them in `AccessToken.claims`). |
| Policy delivery | registryd serves the signed bundle, HS256 | **Built:** same path; switch `keys.valkyrie-ci.algorithm` to RS256 and sign with a KMS-held private key; ship `decision_logs` to a collector instead of console |
| Registry | registryd on a local state file | **Built:** same path; run registryd with a PVC (`deploy/k8s/registryd.yaml`) or implement `store.Store` on Postgres for HA; gateways poll with ETag and keep the last good copy |
| Idempotency, rate limits | in-process bounded TTL store | **Built:** `store.Redis` — set `VALKYRIE_REDIS_ADDR` (required when `VALKYRIE_ENV=prod`) |
| Guardrails | permissive | `VALKYRIE_ENV=prod` refuses to start with the dev auth secret, a short lease key, no Redis, or a wildcard adapter host list (`config.Validate`) |
| Servers | one process each on localhost | one Deployment each, dedicated ServiceAccount, `NetworkPolicy` allowing ingress only from the gateway and egress only to the target |
| Gateway | `go run` | distroless static image (`gateway/Dockerfile`), 3+ replicas, OPA sidecar per pod (`deploy/k8s/gateway.yaml`) |
| Audit | `.dev/audit.jsonl` | stdout → collector → immutable store + SIEM |
| Observability | `/metrics` and audit JSONL | scrape `/metrics` (calls by outcome, denies by reason, latency histogram per tool, open circuits); join audit `decision_id` with OPA decision logs |

Language guidance, in one paragraph: the gateway stays Go (goroutine per connection, `context` cancellation, static binary for the one process holding leases). Servers are Python by default — thin, I/O-bound adapters owned by the system's team — and move to Go individually when a p99 says so; the gateway's per-server semaphore and circuit breaker mean a slow Python server degrades one tool, not the platform. Rust is the right choice for a sandboxed code-execution host; adopt it there if the team has Rust engineers.

---

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `denied` with `policy_unavailable` | OPA not reachable at `VALKYRIE_OPA_URL` | `curl localhost:8181/health`; check `.dev/opa.log` |
| `denied` with `tool_not_bound_to_role` | tool missing from the role's list in `data.json` | add it; `opa test policies` |
| `denied` with `missing_customer_context` on a cart | agent did not attach `customer` | pass `customer=` to `invoke`; check the state key is declared in the `TypedDict` |
| `unknown_tool` | manifest not built or misnamed | `make registry`; file name must equal `name` |
| `invalid_arguments` | schema mismatch, often `additionalProperties` | fix the call; the gateway never coerces |
| server exits with code 2 | a `@mcp.tool` has no manifest | add the manifest |
| `upstream_error: circuit open` | server failed 5 times in a row | check the server log; the circuit closes after 10 s |
| `upstream_error: http 401` from a server | token scope ≠ manifest `credentials.scope` | align the manifest scope with `make_server(scope=…)` |
| `timeout after Nms` | server slower than `limits.timeout_ms` | raise the limit in the manifest (PR) or fix the server |
| `rate_limited` | more than `limits.rate_per_minute` calls for this tenant this minute | back off; raise the limit in the manifest if it is wrong |
| publish fails with `contract test failed` | tool missing on the server, schema mismatch, or registryd cannot authenticate to the server | read `contract.problems`; for first-party servers both sides need the same `VALKYRIE_LEASE_KEY` |
| OPA `Bundle load failed: scope mismatch` / `digest mismatch` | `signing.scope` not set, or a hand-built bundle | use registryd's `/v1/bundle.tar.gz`; `deploy/opa-config.yaml` sets `scope: valkyrie` |
| `credential_broker: static credentials: X is not set` | the secret env var is missing on the **gateway** (not the agent, not the server) | mount it into the gateway pod |
| gateway refuses to start in prod | `config.Validate` found a dev default | the log names the variable |

---

## 12. Contributing

- `make fmt` before committing (gofmt + `opa fmt`).
- Every policy rule ships with a test for its allow path and its deny reason.
- Every gateway change that touches `pipeline.go` ships with a test in `pipeline_test.go` that proves the deny path still never leases or executes.
- Manifests, policy data and role bindings are reviewed by the owning team listed in the manifest (`CODEOWNERS` maps `registry/manifests/<server>.*` to that team).
- Commit messages follow Conventional Commits; `policy:` and `registry:` scopes trigger the bundle and registry publish jobs.
