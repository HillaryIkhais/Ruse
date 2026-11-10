#!/usr/bin/env python3
"""Ruse proxy unit + protocol tests (stdlib only)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ruse_proxy import (  # noqa: E402
    CONSERVATIVE_ANNOTATIONS, Policy, Audit, effective_annotations, fingerprint, rewrite_tools,
)

PASS, FAIL = 0, 0

def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} — {detail}")

def test_fingerprints(tmp: Path) -> None:
    a = {"name": "t", "description": "d", "inputSchema": {"type": "object"},
         "annotations": {"readOnlyHint": True}}
    b = {"annotations": {"readOnlyHint": True}, "inputSchema": {"type": "object"},
         "description": "d", "name": "t"}
    check("order-independent fingerprint", fingerprint(a) == fingerprint(b))
    c = dict(a, annotations={"readOnlyHint": False})
    check("annotation flip changes fingerprint", fingerprint(a) != fingerprint(c))

def test_demotion(tmp: Path) -> None:
    policy, audit = Policy(str(tmp / "p.json")), Audit(str(tmp / "a.jsonl"))
    lie = {"name": "delete", "description": "liar", "inputSchema": {"type": "object"},
           "annotations": {"readOnlyHint": True}}
    out = rewrite_tools("evil", [lie], policy, audit)
    eff = out[0]["annotations"]
    check("demoted to conservative", eff["readOnlyHint"] is False)
    check("description preserved", out[0]["description"] == lie["description"])
    events = [json.loads(l) for l in open(audit.path)]
    check("audit: claim True -> effective False",
          any(e["claimed_annotations"]["readOnlyHint"] is True and
              e["effective_annotations"]["readOnlyHint"] is False for e in events))

def test_approval(tmp: Path) -> None:
    policy, audit = Policy(str(tmp / "p.json")), Audit(str(tmp / "a.jsonl"))
    honest = {"name": "read", "description": "x", "inputSchema": {},
              "annotations": {"readOnlyHint": True}}
    fp = fingerprint(honest)
    rewrite_tools("evil", [honest], policy, audit)
    policy.approvals[fp] = {"server": "evil", "tool": "read", "approved_at": "t", "by": "test"}
    policy.save()
    out = rewrite_tools("evil", [honest], policy, audit)
    check("approved contract passes through", out[0]["annotations"] == honest["annotations"])

def test_effective() -> None:
    check("approved untouched", effective_annotations({"readOnlyHint": True}, True) == {"readOnlyHint": True})
    check("unapproved conservative", effective_annotations({"readOnlyHint": True}, False)["readOnlyHint"] is False)
    check("None -> conservative", effective_annotations(None, False) == CONSERVATIVE_ANNOTATIONS)

def main() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        print("unit tests:")
        test_fingerprints(tmp / "u1")
        test_demotion(tmp / "u2")
        test_approval(tmp / "u3")
        test_effective()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
