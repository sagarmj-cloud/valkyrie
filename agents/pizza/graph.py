# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Pizza-ordering multi-agent graph on LangGraph.

Three agents, one gateway:

    concierge  (role=concierge) reads the profile and delegates
    menu       (role=menu)      searches and shortlists dishes
    ordering   (role=ordering)  carts, orders, charges, quotes the ETA

Each agent has its own gateway client with its own signed identity, so the
policy sees exactly which role is calling. No agent holds a credential.

The "LLM" is pluggable. The default planner is deterministic so the whole
system runs offline in CI; set VALKYRIE_LLM=anthropic (or openai) with an
API key to let a model drive the same tool loop through LangChain.
"""
from __future__ import annotations

import os
import uuid
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

from valkyrie import GatewayClient, InvokeResult, Status, mint_dev_token

GATEWAY = os.environ.get("VALKYRIE_URL", "http://127.0.0.1:8080")
SECRET = os.environ.get("VALKYRIE_AUTH_SECRET", "dev-secret-change-me")
TENANT = os.environ.get("VALKYRIE_TENANT", "acme")


# ------------------------------------------------------------------ state
class AgentState(TypedDict, total=False):
    messages: Annotated[list[dict[str, Any]], add_messages]
    run_id: str
    user: str
    customer_id: str
    request: str
    customer: dict[str, Any]          # loaded from profile (already redacted by the gateway)
    customer_ctx: dict[str, Any]      # the slice the policy needs: diet, allergens, budget
    candidates: list[dict[str, Any]]  # menu shortlist
    rejected: list[str]               # dishes the policy refused, with reasons
    cart: dict[str, Any]
    order: dict[str, Any]
    charge: dict[str, Any]
    eta: dict[str, Any]
    pending_approval: dict[str, Any] | None
    approval: dict[str, Any] | None
    budget: dict[str, Any]
    token_budget: dict[str, Any]      # for the delegation policy: tokens_used / token_limit
    tokens: dict[str, str]            # role -> gateway-issued delegated token (specialists never mint their own)
    chain: list[str]
    trace: list[dict[str, Any]]       # every gateway call, for the demo printout
    reply: str


def client_for(role: str, state: AgentState) -> GatewayClient:
    """The supervisor's token is the on-behalf-of token (dev: minted; production:
    from the IdP). A specialist's token was issued by the gateway at the handoff
    and already carries the end user and the attested chain."""
    token = state.get("tokens", {}).get(role)
    if token is None:
        token = mint_dev_token(SECRET, sub=state["user"], tenant_id=TENANT, agent_id=f"{role}-01", agent_role=role,
                               chain=state.get("chain", []))
    return GatewayClient(GATEWAY, token, trace_id=state["run_id"])


def call(state: AgentState, role: str, tool: str, args: dict[str, Any], **ctx: Any) -> InvokeResult:
    """One tool call through the gateway, recorded on the state's trace."""
    c = client_for(role, state)
    try:
        key = f"{state['run_id']}:{tool}:{uuid.uuid5(uuid.NAMESPACE_OID, repr(sorted(args.items())))}"
        res = c.invoke(tool, args, customer=state.get("customer_ctx"), approval=state.get("approval"),
                       budget=state.get("budget"), idempotency_key=key, **ctx)
    finally:
        c.close()
    state.setdefault("trace", []).append({"agent": role, "tool": tool, "args": args, "status": res.status.value,
                                          "reason": res.reason, "redacted": res.redacted, "decision_id": res.decision_id})
    return res


# Trust levels are a property of the agent fleet, not of a run; in production they
# come from the registry's role bindings. required_trust is what the task needs.
TRUST = {"menu-01": 2, "ordering-01": 3}


def handoff(state: AgentState, role: str, target: str, target_role: str, required_trust: int = 1) -> str | None:
    """PEP 2: ask the gateway before delegating. The caller and its chain come from
    the signed token, so a node cannot shorten or forge its own ancestry. On allow
    the gateway issues the specialist's token (end user, target role, chain + caller);
    on deny there is no token, so an unapproved handoff cannot act at all."""
    c = client_for(role, state)
    try:
        res = c.delegate({"id": target, "role": target_role, "tenant_id": TENANT, "trust_level": TRUST.get(target, 1)},
                         {"required_trust": required_trust, "est_tokens": 2000}, budget=state.get("token_budget"))
    finally:
        c.close()
    state.setdefault("trace", []).append({"agent": role, "tool": f"delegate:{target}", "args": {},
                                          "status": "ok" if res.allow else "denied", "reason": res.reason,
                                          "redacted": [], "decision_id": res.decision_id})
    return res.token if res.allow else None


def customer_ctx(profile: dict[str, Any]) -> dict[str, Any]:
    """The slice of the profile the policy needs. Never the contact details."""
    return {"id": profile.get("customer_id"), "diet": profile.get("diet"), "allergens": profile.get("allergens", []),
            "budget_usd": profile.get("budget_usd")}


# ------------------------------------------------------------------ nodes
def concierge(state: AgentState) -> dict[str, Any]:
    """PEP 1 happened at the API gateway; this is the first tool call."""
    res = call(state, "concierge", "profile.get_preferences", {"customer_id": state["customer_id"]})
    if not res.ok:
        return {"reply": f"Sorry — I couldn't load your profile ({res.as_tool_message()})", "trace": state["trace"]}
    profile = res.json()
    out = {"customer": profile, "customer_ctx": customer_ctx(profile), "chain": ["concierge-01"],
           "budget": {"usd_used": 0.0, "usd_limit": 5.0}, "token_budget": {"tokens_used": 0, "token_limit": 100000},
           "trace": state["trace"], "tokens": {}}
    # The supervisor fans out: each specialist gets its own gateway-issued identity.
    for target, role in (("menu-01", "menu"), ("ordering-01", "ordering")):
        tok = handoff({**state, **out}, "concierge", target, role)
        if tok is None:
            out["reply"] = f"Sorry — I'm not allowed to hand this to the {role} agent right now."
            return out
        out["tokens"][role] = tok
    return out


def menu_agent(state: AgentState) -> dict[str, Any]:
    c = state["customer"]
    res = call(state, "menu", "menu.search_menu",
               {"query": "dinner", "vegetarian": c.get("diet") == "vegetarian", "max_price_usd": c.get("budget_usd")})
    if not res.ok:
        return {"candidates": [], "trace": state["trace"]}
    items = res.json().get("items", [])
    # Rank: taste history first, then cheapest. (A real planner would let the model rank; the
    # policy, not the ranking, is what keeps the customer safe.)
    history = c.get("taste_history", [])
    rank = {name: i for i, name in enumerate(history)}
    items.sort(key=lambda m: (rank.get(m["item"], len(history)), m["price_usd"]))
    # Deliberately keep Pesto Pasta in front if present so the policy gate is exercised.
    items.sort(key=lambda m: m["item"] != "Pesto Pasta")
    return {"candidates": items, "trace": state["trace"]}


def ordering_agent(state: AgentState) -> dict[str, Any]:
    """Try candidates in order. A deny is a normal result: read the reason, move on."""
    if state.get("reply"):
        return {}
    rejected: list[str] = []
    cart: dict[str, Any] | None = None
    for cand in state["candidates"]:
        res = call(state, "ordering", "orders.create_cart", {"customer_id": state["customer_id"], "items": [cand["item"]]})
        if res.ok:
            cart = res.json()
            break
        if res.status == Status.DENIED:
            rejected.append(f"{cand['item']} — {'; '.join(res.reason)}")
            continue
        return {"reply": f"Ordering failed: {res.as_tool_message()}", "rejected": rejected, "trace": state["trace"]}
    if cart is None:
        return {"reply": "Nothing on the menu fits your diet and budget tonight.", "rejected": rejected, "trace": state["trace"]}

    order = call(state, "ordering", "orders.place_order", {"cart_id": cart["cart_id"], "deliver_by": "19:00"})
    if not order.ok:
        return {"reply": order.as_tool_message(), "cart": cart, "rejected": rejected, "trace": state["trace"]}
    order_j = order.json()

    charge = call(state, "ordering", "payments.charge",
                  {"order_id": order_j["order_id"], "amount_usd": order_j["total_usd"], "payment_token": state["customer"]["payment_token"]})
    if charge.status == Status.APPROVAL_REQUIRED:
        return {"cart": cart, "order": order_j, "rejected": rejected, "trace": state["trace"],
                "pending_approval": {"tool": "payments.charge", "amount_usd": order_j["total_usd"], "order_id": order_j["order_id"]}}
    if not charge.ok:
        return {"reply": f"Payment failed: {charge.as_tool_message()}", "cart": cart, "order": order_j, "rejected": rejected, "trace": state["trace"]}

    eta = call(state, "ordering", "delivery.quote_eta", {"order_id": order_j["order_id"]})
    return {"cart": cart, "order": order_j, "charge": charge.json(), "eta": eta.json() if eta.ok else {},
            "rejected": rejected, "trace": state["trace"]}


def approval(state: AgentState) -> dict[str, Any]:
    """Human in the loop. The graph pauses here; the checkpointer persists it;
    a signed Command(resume={"ticket_id": "APR-..."}) continues it."""
    decision = interrupt({"question": "Charge exceeds the auto-approval limit. Approve?", **state["pending_approval"]})
    ticket = decision.get("ticket_id") if isinstance(decision, dict) else None
    if not ticket:
        return {"reply": "Order placed but not paid: the charge was not approved.", "pending_approval": None}
    st = dict(state)
    st["approval"] = {"ticket_id": ticket}
    charge = call(st, "ordering", "payments.charge",
                  {"order_id": state["order"]["order_id"], "amount_usd": state["order"]["total_usd"],
                   "payment_token": state["customer"]["payment_token"]})
    eta = call(st, "ordering", "delivery.quote_eta", {"order_id": state["order"]["order_id"]})
    return {"approval": {"ticket_id": ticket}, "charge": charge.json() if charge.ok else {}, "eta": eta.json() if eta.ok else {},
            "pending_approval": None, "trace": st["trace"]}


def confirm(state: AgentState) -> dict[str, Any]:
    if state.get("reply"):
        return {}
    order, eta = state.get("order", {}), state.get("eta", {})
    skipped = ""
    if state.get("rejected"):
        skipped = " I skipped " + "; ".join(r.split(" — ")[0] + " (" + r.split(" — ")[1].split(":")[0].replace("_", " ") + ")" for r in state["rejected"]) + "."
    items = ", ".join(order.get("items", []))
    return {"reply": f"Done — {items} from Luigi's, ${order.get('total_usd', 0):.2f} including tip, "
                     f"arriving in about {eta.get('eta_minutes', '?')} minutes. Order {order.get('order_id')}.{skipped}"}


def route_after_ordering(state: AgentState) -> str:
    if state.get("pending_approval"):
        return "approval"
    return "confirm"


def build_graph(checkpointer: Any = None):
    g = StateGraph(AgentState)
    g.add_node("concierge", concierge)
    g.add_node("menu", menu_agent)
    g.add_node("ordering", ordering_agent)
    g.add_node("approval", approval)
    g.add_node("confirm", confirm)
    g.add_edge(START, "concierge")
    g.add_conditional_edges("concierge", lambda s: "confirm" if s.get("reply") else "menu")
    g.add_edge("menu", "ordering")
    g.add_conditional_edges("ordering", route_after_ordering)
    g.add_edge("approval", "confirm")
    g.add_edge("confirm", END)
    return g.compile(checkpointer=checkpointer)


def new_state(request: str, *, user: str = "jane.doe", customer_id: str = "c-42") -> AgentState:
    return {"run_id": uuid.uuid4().hex[:12], "user": user, "customer_id": customer_id, "request": request,
            "messages": [{"role": "user", "content": request}], "trace": [], "chain": []}


__all__ = ["build_graph", "new_state", "AgentState", "Command"]
