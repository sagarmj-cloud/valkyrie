#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
"""Replay policy-corpus/*.json through `opa eval` and compare decisions.
Exit non-zero on the first mismatch. Run by `make policy-test` and CI."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPA = os.environ.get("OPA_BIN", "opa")


def evaluate(rule: str, inp: dict) -> dict:
    out = subprocess.run([OPA, "eval", "--format", "json", "--ignore=tests", "--data", str(ROOT / "policies"),
                          "--stdin-input", f"data.{rule.replace('/', '.')}"],
                         input=json.dumps(inp), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]


def main() -> int:
    failures = 0
    cases = sorted((ROOT / "policy-corpus").glob("*.json"))
    for path in cases:
        case = json.loads(path.read_text())
        got = evaluate(case["rule"], case["input"])
        exp = case["expect"]
        problems = []
        if got.get("allow") != exp["allow"]:
            problems.append(f"allow={got.get('allow')} expected {exp['allow']}")
        for r in exp.get("deny_reason_contains", []):
            if not any(d.startswith(r) for d in got.get("deny_reason", [])):
                problems.append(f"missing deny reason {r!r} (got {got.get('deny_reason')})")
        for k, v in exp.get("obligations", {}).items():
            if got.get("obligations", {}).get(k) != v:
                problems.append(f"obligation {k}={got.get('obligations', {}).get(k)} expected {v}")
        status = "ok  " if not problems else "FAIL"
        print(f"  {status} {path.name:<36} {case['name']}")
        for p in problems:
            print(f"         {p}")
        failures += bool(problems)
    print(f"corpus: {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
