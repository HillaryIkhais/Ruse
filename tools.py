#!/usr/bin/env python3
"""Ruse tool handlers — the governed surface the model can reach.

Every handler delegates to the broker thread. There is no code path here
that touches the network, the filesystem (beyond lease/receipt files) or
the browser except through a lease decision.
"""

from __future__ import annotations

import json
import os
import re
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
    # Derive from the active Hermes profile, not a hardcoded ~/.hermes path:
    # every profile gets its own lease, receipt and browser-profile store.
    home = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
    return os.path.join(home, "plugin-data", "ruse")


def leases_dir() -> str:
    return os.path.join(data_dir(), "leases")


# A lease is selected by a plain owner-provisioned name only. The regex makes
# "../x" and "/abs/x" impossible; the realpath containment check below is
# defence in depth (symlinks, future schema changes).
_LEASE_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CRED_SECRET_ENV = "RUSE_CRM_PASSWORD"


def resolve_lease_path(name: Any) -> tuple[str | None, str | None]:
    """Resolve a model-supplied lease name to a contained lease path.

    Returns (path, None) on success or (None, error) on rejection. No model
    input is ever joined into a path without first passing the strict name
    check and the realpath containment check.
    """
    if not isinstance(name, str) or not _LEASE_NAME_RE.fullmatch(name):
        return None, ("invalid lease name — use 1-64 characters from "
                      "[A-Za-z0-9_-] (e.g. 'crm'); paths are not accepted")
    base = os.path.realpath(leases_dir())
    candidate = os.path.realpath(os.path.join(base, f"{name}.json"))
    try:
        if os.path.commonpath([base, candidate]) != base:
            return None, "lease path escapes the leases directory"
    except ValueError:
        return None, "lease path escapes the leases directory"
    return candidate, None


def resolve_login_password() -> str:
    """Resolve the CRM password from Hermes' profile-scoped secret store.

    The password is never read from a plaintext file inside the plugin data
    dir. If no secret is configured, auto-login is skipped (fail closed) and
    the owner can sign in once in the persistent profile instead.
    """
    try:
        from agent.secret_scope import get_secret  # type: ignore
        return get_secret(_CRED_SECRET_ENV, "") or ""
    except Exception:  # noqa: BLE001 — no secret scope in standalone tests
        return ""


def _broker():
    if _STATE["broker"] is None:
        _STATE["broker"] = broker_mod.Broker(data_dir())
    return _STATE["broker"]


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def ruse_connect(args: dict, **kwargs) -> str:
    name = args.get("lease") or ""
    lease_path, err = resolve_lease_path(name)
    if err:
        return _json({"ok": False, "error": err})
    assert lease_path is not None
    if not os.path.isfile(lease_path):
        return _json({"ok": False,
                      "error": f"no lease named {name!r}",
                      "hint": "the owner places a lease file under "
                              "plugin-data/ruse/leases/; the model cannot "
                              "create or select leases"})
    # Password comes from the profile-scoped Hermes secret store, never from
    # a plaintext file the model could read or write.
    password = resolve_login_password()
    try:
        result = _broker()._invoke("connect", lease_path, password)
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
