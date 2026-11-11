#!/usr/bin/env python3
"""Ruse tool handlers — the governed surface the model can reach.

Every handler delegates to the broker thread. There is no code path here
that touches the network, the filesystem (beyond lease/receipt files) or
the browser except through a lease decision.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import broker as broker_mod  # noqa: E402

_STATE: Dict[str, Any] = {"broker": None, "data_dir": None}


def _config_data_dir() -> str | None:
    """Read plugins.entries.ruse.settings.data_dir from the Hermes config file directly.

    ctx.get_config() isn't available in tool handlers (only args/kwargs), and the
    plugin host child process may not inherit RUSE_DATA_DIR. Reading the config
    file directly is the reliable fallback. Minimal indentation-based parse for
    the specific section we need (no PyYAML dependency)."""
    home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    cfg_path = os.path.join(home, "config.yaml")
    if not os.path.exists(cfg_path):
        return None
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return None
    # Walk the tree: plugins -> entries -> ruse -> settings -> data_dir
    section = None  # current section name at each indent level
    indent_stack: list[tuple[int, str]] = []  # (indent, section)
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        # Pop stack to current indent
        while indent_stack and indent_stack[-1][0] >= indent:
            indent_stack.pop()
        if val == "":
            # new section
            indent_stack.append((indent, key))
            if indent_stack == [(0, "plugins"), (2, "entries"), (4, "ruse"), (6, "settings")]:
                section = "settings"
            else:
                section = None
        else:
            # leaf value
            path = [s for _, s in indent_stack] + [key]
            if path == ["plugins", "entries", "ruse", "settings", "data_dir"]:
                return val.strip('"').strip("'")
    return None


def data_dir() -> str:
    d = _STATE["data_dir"]
    if d:
        return d
    env_d = os.environ.get("RUSE_DATA_DIR")
    if env_d:
        return env_d
    cfg_d = _config_data_dir()
    if cfg_d:
        return cfg_d
    return os.path.expanduser("~/.hermes/plugin-data/ruse")


def leases_dir() -> str:
    return os.path.join(data_dir(), "leases")


def _broker():
    if _STATE["broker"] is None:
        _STATE["broker"] = broker_mod.Broker(data_dir())
    return _STATE["broker"]


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def ruse_connect(args: dict, **kwargs) -> str:
    explicit_dd = args.get("data_dir")
    if explicit_dd:
        _STATE["data_dir"] = explicit_dd
    name = args.get("lease") or ""
    lease_path = args.get("lease_path") or os.path.join(leases_dir(), f"{name}.json")
    creds = args.get("credentials_path") or os.path.join(data_dir(), "credentials.json")
    if not os.path.exists(lease_path):
        return _json({"ok": False,
                      "error": f"no lease file {lease_path}",
                      "hint": "the owner places a signed lease file there; "
                              "the model cannot create leases"})
    try:
        result = _broker()._invoke("connect", lease_path, creds)
        return _json(result)
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_inspect(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("inspect"))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_navigate(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("navigate", args.get("path", "/")))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_fill(args: dict, **kwargs) -> str:
    def _fill(state, selector: str, value: str):
        page = state.st["page"]
        page.fill(selector, value)
        return {"ok": True, "filled": selector}
    try:
        return _json(_broker()._invoke(_fill, args.get("selector", ""),
                                       args.get("value", "")))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_prepare(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("prepare", args.get("path", "/"),
                                       args.get("body") or {},
                                       args.get("method", "POST")))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_commit(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("commit", args.get("proposal_id", "")))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_verify(args: dict, **kwargs) -> str:
    def _verify(state):
        page, session = state.st["page"], state.st["session"]
        if page is None or session is None:
            raise RuntimeError("not connected")
        origin = session.spec["browser"]["allowed_origins"][0]
        from urllib.parse import urlparse
        path = urlparse(page.url).path
        r = page.request.get(origin + path)
        return {"url": page.url, "status_code": r.status, "body": r.text()[:400]}
    try:
        return _json(_broker()._invoke(_verify))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_revoke(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("revoke"))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_status(args: dict, **kwargs) -> str:
    try:
        return _json(_broker()._invoke("status"))
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def ruse_receipts(args: dict, **kwargs) -> str:
    try:
        return _json({"receipts": _broker()._invoke("receipts", int(args.get("n", 20)))})
    except Exception as exc:  # noqa: BLE001
        return _json({"ok": False, "error": str(exc)})


def shutdown() -> None:
    b = _STATE["broker"]
    if b is not None:
        try:
            b._invoke("shutdown")
        except Exception:
            pass
        _STATE["broker"] = None
