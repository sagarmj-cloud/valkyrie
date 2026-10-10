#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Run the pizza scenario end to end against a live gateway and print every
policy decision. `make demo` starts the whole stack and calls this."""
import json
import sys

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from graph import build_graph, new_state

REQUEST = "Order me something good for dinner. I'm vegetarian with a nut allergy, keep it under $25 and have it here by 7 pm."


def main() -> int:
    graph = build_graph(checkpointer=InMemorySaver())
    cfg = {"configurable": {"thread_id": "demo-1"}}
    print(f"\n🧑  Customer: “{REQUEST}”\n")
    result = graph.invoke(new_state(REQUEST), cfg)

    # Human-in-the-loop: if the graph paused for approval, approve it with a ticket.
    if "__interrupt__" in result:
        intr = result["__interrupt__"][0].value
        print(f"⏸   Paused for approval: {json.dumps(intr)}")
        result = graph.invoke(Command(resume={"ticket_id": "APR-7781"}), cfg)

    print("─" * 78)
    print("  AGENT       TOOL / HANDOFF            STATUS             DETAIL")
    print("─" * 78)
    for t in result.get("trace", []):
        detail = "; ".join(t["reason"]) if t["reason"] else (f"redacted {t['redacted']}" if t["redacted"] else "")
        mark = {"ok": "✅", "denied": "⛔", "approval_required": "⏸ "}.get(t["status"], "⚠️ ")
        print(f"  {t['agent']:<11} {t['tool']:<25} {mark} {t['status']:<16} {detail}")
    print("─" * 78)
    print(f"\n🤖  Agent: “{result.get('reply')}”\n")
    ok = any(t["status"] == "denied" and "allergen_conflict" in ";".join(t["reason"]) for t in result.get("trace", []))
    ok = ok and bool(result.get("charge")) and bool(result.get("eta"))
    print("DEMO", "PASSED" if ok else "FAILED", "— the policy gate refused the pesto pasta and the agent recovered." if ok else "")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
