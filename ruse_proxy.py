#!/usr/bin/env python3
"""Ruse — owner-controlled safety contracts for MCP tool annotations.

A stdio MCP proxy that sits between Hermes and any MCP server. The server's
tool annotations (readOnlyHint / destructiveHint / idempotentHint / openWorldHint)
are advisory claims made by the very server whose safety they describe.
Ruse never lets an unapproved server promote its own tools:

  * every tools/list response is intercepted.
  * each tool contract (name, description, schemas, annotations) is fingerprinted
    with SHA-256.
  * a contract the owner has explicitly approved as read-only passes through.
  * every other contract is rewritten to conservative annotations:
    readOnlyHint=false, destructiveHint=true, idempotentHint=false, openWorldHint=true.
  * Any change to a contract changes the fingerprint, auto-revoking approval.

Usage:
    ruse_proxy.py [--policy PATH] [--audit PATH] [--name SERVER] -- CMD [ARGS...]

Diagnostics go to stderr; stdout carries MCP protocol traffic only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from typing import Any, Dict, Optional

CONSERVATIVE_ANNOTATIONS: Dict[str, Any] = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def _log(msg: str) -> None:
    sys.stderr.write(f"[ruse] {msg}\n")
    sys.stderr.flush()


def contract_of(tool: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
        "outputSchema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
    }


def fingerprint(tool: Dict[str, Any]) -> str:
    canonical = json.dumps(contract_of(tool), sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Policy:
    def __init__(self, path: str):
        self.path = path
        self.approvals: Dict[str, Dict[str, Any]] = {}
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.last_seen: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.approvals = data.get("approvals", {})
            self.contracts = data.get("contracts", {})
            self.last_seen = data.get("last_seen", {})
        except FileNotFoundError:
            pass
        except Exception as exc:
            _log(f"policy file unreadable ({exc}); treating as empty (fail closed: nothing approved)")

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = f"{self.path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "approvals": self.approvals,
                       "contracts": self.contracts, "last_seen": self.last_seen},
                      fh, indent=2, sort_keys=True, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def is_approved(self, fp: str) -> bool:
        return fp in self.approvals

    def remember(self, key: str, fp: str, contract: Dict[str, Any]) -> Optional[str]:
        prev = self.last_seen.get(key)
        self.last_seen[key] = fp
        self.contracts[fp] = contract
        referenced = set(self.last_seen.values()) | set(self.approvals)
        for stale in [h for h in self.contracts if h not in referenced]:
            del self.contracts[stale]
        return prev if prev != fp else None


class Audit:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, event: Dict[str, Any]) -> None:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
        self._fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        self._fh.flush()


def effective_annotations(claimed: Optional[Dict[str, Any]], approved: bool) -> Optional[Dict[str, Any]]:
    if approved:
        return claimed
    merged = dict(claimed) if claimed else {}
    merged.update(CONSERVATIVE_ANNOTATIONS)
    return merged


def rewrite_tools(server: str, tools: list, policy: Policy, audit: Audit) -> list:
    policy._load()
    out = []
    for tool in tools:
        if not isinstance(tool, dict) or "name" not in tool:
            out.append(tool)
            continue
        fp = fingerprint(tool)
        claimed = tool.get("annotations")
        approved = policy.is_approved(fp)
        key = f"{server}/{tool['name']}"
        prev = policy.remember(key, fp, contract_of(tool))
        changed = prev is not None
        eff = effective_annotations(claimed, approved)
        rewritten = dict(tool)
        rewritten["annotations"] = eff
        audit.write({
            "event": "tools/list", "server": server, "tool": tool["name"],
            "fingerprint": fp, "claimed_annotations": claimed,
            "effective_annotations": eff, "approved": approved,
            "contract_changed": changed, "previous_fingerprint": prev,
            "revoked_by_change": changed and policy.is_approved(prev) if prev else False,
        })
        if changed:
            _log(f"contract changed for {key}: {prev[:12]} -> {fp[:12]}"
                 + (" (previous approval revoked)" if policy.is_approved(prev) else ""))
        out.append(rewritten)
    policy.save()
    return out


def maybe_rewrite(server: str, msg: Dict[str, Any], policy: Policy, audit: Audit) -> Dict[str, Any]:
    result = msg.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        result["tools"] = rewrite_tools(server, result["tools"], policy, audit)
    return msg


def run_proxy(args: argparse.Namespace) -> int:
    policy = Policy(args.policy)
    audit = Audit(args.audit)
    server = args.name or "mcp-server"

    try:
        child = subprocess.Popen(
            args.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
        )
    except Exception as exc:
        _log(f"failed to start child {args.cmd!r}: {exc}")
        return 1

    _log(f"proxying {server} -> {' '.join(args.cmd)} (policy: {args.policy})")

    pending: Dict[str, str] = {}

    def pump_stdin() -> None:
        try:
            for raw in sys.stdin.buffer:
                line = raw.rstrip(b"\r\n")
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if isinstance(msg, dict) and "method" in msg and "id" in msg:
                        pending[json.dumps(msg["id"])] = msg["method"]
                except Exception:
                    pass
                child.stdin.write(line + b"\n")
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()
            except Exception:
                pass

    def pump_stdout() -> None:
        try:
            for raw in child.stdout:
                line = raw.rstrip(b"\r\n")
                if not line:
                    continue
                out = line
                try:
                    msg = json.loads(line)
                except Exception:
                    msg = None
                if isinstance(msg, dict) and "id" in msg:
                    method = pending.pop(json.dumps(msg["id"]), None)
                    if method in ("tools/list", "server/discover") or (
                            isinstance(msg.get("result"), dict)
                            and isinstance(msg["result"].get("tools"), list)):
                        msg = maybe_rewrite(server, msg, policy, audit)
                        out = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                sys.stdout.buffer.write(out + b"\n")
                sys.stdout.buffer.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                sys.stdout.buffer.flush()
            except Exception:
                pass

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda s, f: child.send_signal(s))
        except Exception:
            pass

    import threading
    t_in = threading.Thread(target=pump_stdin, daemon=True)
    t_out = threading.Thread(target=pump_stdout, daemon=True)
    t_in.start()
    t_out.start()

    rc = child.wait()
    t_in.join(timeout=5)
    t_out.join(timeout=5)
    try:
        os.killpg(os.getpgid(child.pid), signal.SIGKILL)
    except Exception:
        pass
    _log(f"child exited rc={rc}")
    return rc


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Ruse MCP annotation-enforcing proxy")
    parser.add_argument("--policy", default=os.environ.get("RUSE_POLICY", "~/.hermes/plugin-data/ruse/policy.json"))
    parser.add_argument("--audit", default=os.environ.get("RUSE_AUDIT", "~/.hermes/plugin-data/ruse/audit.jsonl"))
    parser.add_argument("--name", default=None, help="MCP server name")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="child command after --")
    args = parser.parse_args(argv)
    if args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    if not args.cmd:
        _log("no child command given (usage: ruse_proxy.py ... -- CMD ARGS...)")
        return 2
    return run_proxy(args)


if __name__ == "__main__":
    sys.exit(main())