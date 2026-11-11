#!/usr/bin/env python3
"""Ruse — bounded browser authority for Hermes.

register(ctx) wires the governed browser toolset. There is no arbitrary
code-execution surface: the model can only connect, look, propose, commit
a frozen proposal, verify, and revoke — all mediated by the lease.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Relative imports so Hermes's own top-level ``schemas``/``tools`` modules
# (already cached in sys.modules) can't shadow the plugin's own modules.
from . import schemas  # noqa: E402
from . import tools  # noqa: E402

TOOLSET = "ruse"


def register(ctx) -> None:
    """Wire schemas to handlers."""
    settings = {}
    try:
        data_dir = ctx.get_config("data_dir")
    except Exception:
        data_dir = None
    if data_dir:
        tools._STATE["data_dir"] = data_dir

    for schema in schemas.ALL:
        name = schema["name"]
        ctx.register_tool(name=name, toolset=TOOLSET,
                          schema=schema, handler=getattr(tools, name))


def shutdown() -> None:
    tools.shutdown()
