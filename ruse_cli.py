#!/usr/bin/env python3
"""Ruse owner CLI — inspect claims, review contracts, approve read-only.

Commands:
    status                       every tool seen: claim vs effective, approval
    diff SERVER/TOOL             the reviewed contract + change history
    approve-readonly SERVER/TOOL approve the exact contract last seen
    revoke SERVER/TOOL           drop an approval
    audit [N]                    last N audit events (default 20)

Approval binds to the full SHA-256 fingerprint shown by `status`/`diff`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ruse_proxy import Policy, Audit, CONSERVATIVE_ANNOTATIONS

def _load(args) -> Policy:
    return Policy(args.policy)

def cmd_status(args) -> int:
    policy = _load(args)
    if not policy.last_seen:
        print("No MCP tools seen yet. Start the proxied server once, then re-run.")
        return 0
    print(f"{'TOOL':44} {'CLAIMED':10} {'EFFECTIVE':10} {'APPROVED':9} FINGERPRINT")
    for key in sorted(policy.last_seen):
        fp = policy.last_seen[key]
        contract = policy.contracts.get(fp, {})
        claimed = contract.get("annotations") or {}
        claimed_ro = claimed.get("readOnlyHint")
        approved = fp in policy.approvals
        eff_ro = claimed_ro if approved else False
        print(f"{key:44} {str(claimed_ro):10} {str(eff_ro):10} "
              f"{'yes' if approved else 'no':9} {fp[:16]}")
    return 0

def cmd_diff(args) -> int:
    policy = _load(args)
    key = args.tool
    fp = policy.last_seen.get(key)
    if fp is None:
        matches = [k for k in policy.last_seen if key in k]
        if len(matches) == 1:
            key = matches[0]
            fp = policy.last_seen[key]
        elif len(matches) > 1:
            print(f"ambiguous: {', '.join(sorted(matches))}")
            return 2
        else:
            print(f"unknown tool: {args.tool}")
            return 1
    contract = policy.contracts.get(fp, {})
    approved = policy.approvals.get(fp)
    print(f"== {key}")
    print(f"fingerprint: {fp}")
    print(f"claimed annotations:    {json.dumps(contract.get('annotations'))}")
    print(f"approval: "
          + (f"APPROVED {approved.get('approved_at')} by {approved.get('by')}"
             if approved else "not approved -> effective annotations are conservative "
                              "(readOnlyHint=false, destructiveHint=true, ...)"))
    print("-- contract as last seen --")
    print(json.dumps(contract, indent=2, ensure_ascii=False, sort_keys=True))
    print(f"\nTo approve exactly this contract:  ruse_cli.py approve-readonly {key}")
    return 0

def cmd_approve(args) -> int:
    policy = _load(args)
    key = args.tool
    fp = policy.last_seen.get(key)
    if fp is None:
        matches = [k for k in policy.last_seen if key in k]
        if len(matches) == 1:
            key = matches[0]
            fp = policy.last_seen[key]
        else:
            print(f"unknown tool: {args.tool} (run `status` first)")
            return 1
    contract = policy.contracts.get(fp, {})
    if contract.get("annotations", {}).get("readOnlyHint") is not True:
        print(f"refusing: the server's own claim for {key} is not readOnlyHint=true")
        if not args.attest:
            return 1
    policy.approvals[fp] = {
        "server": key.split("/")[0],
        "tool": key.split("/")[-1],
        "approved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "by": "owner-cli",
    }
    policy.save()
    Audit(args.audit).write({"event": "approve-readonly", "server": key.split("/")[0],
                             "tool": key.split("/")[-1], "fingerprint": fp,
                             "claimed_annotations": contract.get("annotations")})
    print(f"approved {key} as read-only at fingerprint {fp[:16]}")
    print("Any change to this contract revokes the approval automatically.")
    return 0

def cmd_revoke(args) -> int:
    policy = _load(args)
    key = args.tool
    fp = policy.last_seen.get(key)
    if fp is None:
        matches = [k for k in policy.last_seen if key in k]
        if len(matches) == 1:
            key = matches[0]
            fp = policy.last_seen[key]
        else:
            print(f"unknown tool: {args.tool}")
            return 1
    if policy.approvals.pop(fp, None) is None:
        print(f"{key} was not approved")
        return 1
    policy.save()
    Audit(args.audit).write({"event": "revoke", "server": key.split("/")[0],
                             "tool": key.split("/")[-1], "fingerprint": fp})
    print(f"revoked read-only approval for {key} ({fp[:12]})")
    return 0

def cmd_audit(args) -> int:
    path = args.audit
    if not os.path.exists(path):
        print("no audit trail yet")
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    for line in lines[-args.n:]:
        print(line.rstrip())
    return 0

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ruse owner CLI")
    parser.add_argument("--policy", default=os.path.expanduser("~/.hermes/plugin-data/ruse/policy.json"))
    parser.add_argument("--audit", default=os.path.expanduser("~/.hermes/plugin-data/ruse/audit.jsonl"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="list tools: claim vs effective vs approved")
    p = sub.add_parser("diff", help="show a tool's reviewed contract")
    p.add_argument("tool")
    p = sub.add_parser("approve-readonly", help="approve the last-seen contract as read-only")
    p.add_argument("tool")
    p.add_argument("--attest", action="store_true",
                   help="approve even though the server itself does not claim readOnlyHint")
    p = sub.add_parser("revoke", help="drop an approval")
    p.add_argument("tool")
    p = sub.add_parser("audit", help="show recent audit events")
    p.add_argument("n", nargs="?", type=int, default=20)

    args = parser.parse_args(argv)
    return {"status": cmd_status, "diff": cmd_diff, "approve-readonly": cmd_approve,
            "revoke": cmd_revoke, "audit": cmd_audit}[args.cmd](args)

if __name__ == "__main__":
    sys.exit(main())