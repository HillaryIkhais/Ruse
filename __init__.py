#!/usr/bin/env python3
"""Ruse — bounded browser authority for Hermes.

register(ctx) wires the governed browser toolset. There is no arbitrary
code-execution surface: the model can only connect, look, propose, commit
a frozen proposal, verify, and revoke — all mediated by the lease.
"""

from __future__ import annotations

import sys

if __package__ in (None, ""):
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import schemas  # noqa: E402
import tools  # noqa: E402

TOOLSET = "ruse"


def register(ctx) -> None:
    """Wire schemas to handlers."""
    settings = {}
    try:
        settings = ctx.get_config() or {}
    except Exception:
        settings = {}
    data_dir = settings.get("data_dir") if isinstance(settings, dict) else None
    if data_dir:
        tools._STATE["data_dir"] = data_dir

    for schema in schemas.ALL:
        name = schema["name"]
        ctx.register_tool(name=name, toolset=TOOLSET,
                          schema=schema, handler=getattr(tools, name))


def shutdown() -> None:
    tools.shutdown()
