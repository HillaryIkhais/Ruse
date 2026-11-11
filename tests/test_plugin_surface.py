#!/usr/bin/env python3
"""Plugin-surface smoke test: register(ctx) wiring with a mock context.

Verifies the exact contract Hermes uses: manifest parses, register() runs,
every declared tool registers, handlers return JSON strings.
Run: python3 tests/test_plugin_surface.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # .../ruse package dir
PKG_ROOT = ROOT.parent  # .../Downloads/HERMES (contains ruse/ as a package)
if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS, FAIL = 0, 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} — {detail}")


class FakeCtx:
    def __init__(self, settings=None):
        self.registered = {}
        self._settings = settings or {}

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.registered[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def get_config(self, key=None, default=None):
        if key is None:
            return self._settings
        return self._settings.get(key, default)


def main() -> int:
    return run()


def run() -> int:
    # manifest sanity without a yaml dependency: minimal key checks
    text = (ROOT / "plugin.yaml").read_text()
    for key in ("name: ruse", "manifest_version: 2", "python_dependencies:"):
        check(f"manifest has {key.split(':')[0]}", key in text)

    # tmp data dir so we never touch the real home
    tmp = tempfile.mkdtemp(prefix="ruse-surface-")
    os.environ["RUSE_DATA_DIR"] = tmp
    if "ruse" in sys.modules:
        del sys.modules["ruse"]
    sys.path.insert(0, str(ROOT))
    import importlib
    tools = importlib.import_module("ruse.tools")
    __init__ = importlib.import_module("ruse")

    declared = [l.strip("- ").strip() for l in text.splitlines()
                if l.strip().startswith("- ruse_")]
    ctx = FakeCtx()
    __init__.register(ctx)
    check("register() ran with a mock ctx", len(ctx.registered) == len(declared),
          f"{len(ctx.registered)} registered vs {len(declared)} declared")
    for name in declared:
        check(f"{name} registered", name in ctx.registered)
        schema = ctx.registered[name]["schema"]
        check(f"{name} schema well-formed",
              schema["name"] == name and "description" in schema
              and "parameters" in schema)
        result = ctx.registered[name]["handler"]({})
        parsed = json.loads(result)
        check(f"{name} returns JSON",
              isinstance(parsed, dict) and ("ok" in parsed or "error" in parsed
                                            or "active" in parsed or "receipts" in parsed),
              result[:100])
    tools.shutdown()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(run())
