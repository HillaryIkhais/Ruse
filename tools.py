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


def data_dir() -> str:
    d = _STATE["data_dir"]
    return d or os.environ.get("RUSE_DATA_DIR",
                               os.path.expanduser("~/.hermes/plugin-data/ruse"))


def leases_dir() -> str:
    return os.path.join(data_dir(), "leases")


def _broker():
    if _STATE["broker"] is None:
        _STATE["broker"] = broker_mod.Broker(data_dir())
    return _STATE["broker"]


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def ruse_connect(args: dict, **kwargs) -> str:
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
        return _json(_broker().call(_fill, args.get("selector", ""),
                                    args.get("value", ""))[1])
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
        return _json(_broker().call(_verify)[1])
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
