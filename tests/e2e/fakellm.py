#!/usr/bin/env python3
"""Fake OpenAI-compatible SSE LLM for driving real Hermes end-to-end, offline.

Serves POST /v1/chat/completions as `text/event-stream` SSE chunks.
A step is {"content": "..."} (assistant text) or {"tool": name, "args": {...}}.
Argument values may reference the previous tool result: "$proposal_id".

    SCENARIO=/path/steps.json FAKE_PORT=8715 python3 fakellm.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

STEPS_PATH = os.environ.get("SCENARIO", "")
PORT = int(os.environ.get("FAKE_PORT", "8715"))
MODEL = os.environ.get("FAKE_MODEL", "ruse-fake")
LOCK = threading.Lock()
STATE = {"i": 0}


def load_steps() -> list:
    with open(STEPS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def last_tool_result(messages: list) -> str:
    for m in reversed(messages):
        if m.get("role") == "tool":
            c = m.get("content")
            return c if isinstance(c, str) else json.dumps(c)
    return ""


def substitute(value, last_result: str):
    if isinstance(value, str) and "$" in value:
        for key in re.findall(r"\$(\w+)", value):
            m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', last_result)
            if not m:
                m2 = re.search(rf"'{key}'\s*:\s*'([^']+)'", last_result)
                m = m2 or m
            if m:
                value = value.replace(f"${key}", m.group(1))
    return value


def sse_lines(chunk: dict) -> list:
    return [f"data: {json.dumps(chunk, ensure_ascii=False)}", ""]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        if urlparse(self.path).path not in ("/v1/chat/completions", "/chat/completions"):
            body = json.dumps({"error": "not found"}).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n))
        messages = req.get("messages", [])
        with LOCK:
            steps = load_steps()
            i = STATE["i"]
            STATE["i"] = min(i + 1, len(steps) - 1)
        step = steps[min(i, len(steps) - 1)]
        last = last_tool_result(messages)

        chunks = []
        if "tool" in step:
            args = {k: substitute(v, last) for k, v in step.get("args", {}).items()}
            tool_call = {"id": f"call_{i}", "type": "function",
                         "function": {"name": step["tool"],
                                      "arguments": json.dumps(args)}}
            # first chunk with role + tool_calls
            chunks.append({"id": f"chatcmpl-{i}", "object": "chat.completion.chunk",
                           "created": int(time.time()), "model": MODEL,
                           "choices": [{"index": 0, "delta": {"role": "assistant",
                                                             "tool_calls": [tool_call]},
                                        "finish_reason": None}]})
            # one content chunk (optional, small)
            chunks.append({"id": f"chatcmpl-{i}", "object": "chat.completion.chunk",
                           "created": int(time.time()), "model": MODEL,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        else:
            text = step.get("content", "")
            # stream text one word per chunk
            words = text.split(" ")
            for idx, w in enumerate(words):
                delta = {"content": w + (" " if idx < len(words) - 1 else "")}
                chunks.append({"id": f"chatcmpl-{i}", "object": "chat.completion.chunk",
                               "created": int(time.time()), "model": MODEL,
                               "choices": [{"index": 0, "delta": delta,
                                           "finish_reason": None}]})
            chunks.append({"id": f"chatcmpl-{i}", "object": "chat.completion.chunk",
                           "created": int(time.time()), "model": MODEL,
                           "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})

        body = b""
        for c in chunks:
            body += ("data: " + json.dumps(c, ensure_ascii=False) + "\n\n").encode()
        body += b"data: [DONE]\n\n"

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        return self._send(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    STATE["i"] = 0
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write(f"fake llm (SSE) on 127.0.0.1:{PORT} steps={STEPS_PATH}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
