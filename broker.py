#!/usr/bin/env python3
"""Ruse enforcement broker — owns the browser, enforces the lease.

The broker runs Playwright in a dedicated thread (handlers may be called
from arbitrary threads, so every operation is a queued command). The
browser is a dedicated persistent profile, never the user's everyday
profile. Every outbound request — navigation, form submission, page
fetch/XHR — passes one decision function (lease.LeaseSession.decide)
before it reaches the application.

Enforcement rules in the route handler:
  * enforcement off only during owner-supervised pairing (login);
    it is armed immediately after and never silently disarmed.
  * allowed -> continue; denied -> abort, and the denial is recorded
    as a receipt.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from typing import Any, Dict, Optional

from lease import LeaseSession, load_lease, Decision, LeaseError

# ---------------------------------------------------------------- commands


class _Cmd:
    def __init__(self, fn, *args, **kwargs):
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.reply: queue.Queue = queue.Queue()


class Broker:
    """Thread-safe facade over one Playwright browser governed by a lease."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.receipts_path = os.path.join(data_dir, "receipts.jsonl")
        self.profile_root = os.path.join(data_dir, "browser-profiles")
        self._cmd_q: "queue.Queue[_Cmd]" = queue.Queue()
        self._thread = threading.Thread(target=self._run, daemon=True, name="ruse-broker")
        self._thread.start()

    # -- public API (called from handler threads) -------------------------
    def call(self, fn, *args, **kwargs) -> Any:
        cmd = _Cmd(fn, *args, **kwargs)
        self._cmd_q.put(cmd)
        return cmd.reply.get()  # (ok, result-or-exception)

    def _invoke(self, fn, *args, **kwargs):
        ok, result = self.call(fn, *args, **kwargs)
        if not ok:
            raise result
        return result

    # -- broker thread -----------------------------------------------------
    def _run(self) -> None:
        from playwright.sync_api import sync_playwright
        st: Dict[str, Any] = {"pw": None, "ctx": None, "page": None,
                              "session": None, "enforce": False, "lease_path": None}
        state = _State(st, self.receipts_path, self.profile_root)

        while True:
            cmd = self._cmd_q.get()
            try:
                if isinstance(cmd.fn, str):
                    result = getattr(state, cmd.fn)(*cmd.args, **cmd.kwargs)
                else:
                    result = cmd.fn(state, *cmd.args, **cmd.kwargs)
                cmd.reply.put((True, result))
            except Exception as exc:  # noqa: BLE001
                cmd.reply.put((False, exc))


class _State:
    def __init__(self, st: dict, receipts_path: str, profile_root: str):
        self.st = st
        self.receipts_path = receipts_path
        self.profile_root = profile_root

    # -- receipts ----------------------------------------------------------
    def receipt(self, event: Dict[str, Any]) -> None:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
        with open(self.receipts_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def recent_receipts(self, n: int = 20) -> list:
        try:
            with open(self.receipts_path, encoding="utf-8") as fh:
                return [json.loads(l) for l in fh.readlines()[-n:]]
        except FileNotFoundError:
            return []

    # -- enforcement -------------------------------------------------------
    def _route(self, route) -> None:
        req = route.request
        method = req.method
        url = req.url
        body = None
        if method not in ("GET", "HEAD"):
            raw = req.post_data
            if raw:
                try:
                    body = json.loads(raw)
                except Exception:
                    body = {"_raw": raw[:200]}
        if not self.st["enforce"]:
            route.continue_()
            return
        session: Optional[LeaseSession] = self.st["session"]
        if session is None:
            route.abort()
            self.receipt({"event": "deny", "method": method, "url": url,
                         "reason": "no active lease (fail closed)"})
            return
        d = session.decide(method, url, body)
        self.receipt({"event": "allow" if d.allowed else "deny", "method": method,
                      "url": url, "rule": d.rule, "reason": d.reason, **d.detail})
        if d.allowed:
            if d.rule == "commit.allowed":
                session.consume_commit()
            route.continue_()
        else:
            route.abort()

    # -- lifecycle -----------------------------------------------------------
    def connect(self, lease_path: str, credentials_path: str = "") -> Dict[str, Any]:
        lease = load_lease(lease_path)
        session = LeaseSession(lease)
        self.st["session"] = session
        self.st["lease_path"] = lease_path
        pw = self.st["pw"]
        if pw is None:
            from playwright.sync_api import sync_playwright
            self.st["pw"] = sync_playwright().start()
            pw = self.st["pw"]
        profile = lease["browser"].get("profile", "default")
        profile_dir = os.path.join(self.profile_root, profile)
        origin = lease["browser"]["allowed_origins"][0]
        if self.st["ctx"] is not None:
            try:
                self.st["ctx"].close()
            except Exception:
                pass
        self.st["ctx"] = pw.chromium.launch_persistent_context(
            profile_dir, channel="chrome", headless=True,
            viewport={"width": 1280, "height": 800})
        page = self.st["ctx"].new_page()
        page.route("**/*", self._route)
        self.st["page"] = page
        self.st["enforce"] = False  # pairing: owner-supervised sign-in only

        # owner sign-in through the dedicated profile (credentials never in lease)
        if credentials_path and os.path.exists(credentials_path):
            with open(credentials_path, encoding="utf-8") as fh:
                creds = json.load(fh)
            page.goto(origin + "/", wait_until="load")
            page.fill("input[name=user]", creds["user"])
            page.fill("input[name=pass]", creds["pass"])
            page.click("button")
            page.wait_for_load_state("load")
        self.st["enforce"] = True
        self.receipt({"event": "lease_start", "lease": lease["lease"].get("name"),
                      "origins": lease["browser"]["allowed_origins"],
                      "ttl_seconds": lease["lease"]["ttl_seconds"],
                      "max_commits": lease["lease"]["max_commits"]})
        return {"ok": True, "lease": lease["lease"].get("name"),
                "origins": lease["browser"]["allowed_origins"],
                "expires_at": session.started + session.ttl,
                "commits_left": session.commits_left}

    def navigate(self, path: str) -> Dict[str, Any]:
        page, session = self.st["page"], self.st["session"]
        if page is None or session is None:
            raise LeaseError("not connected")
        origin = session.spec["browser"]["allowed_origins"][0]
        d = session.decide("GET", origin + path)
        if not d.allowed:
            raise LeaseError(f"navigate denied: {d.reason}")
        page.goto(origin + path, wait_until="load")
        return {"url": page.url, "title": page.title()}

    def inspect(self) -> Dict[str, Any]:
        page = self.st["page"]
        if page is None:
            raise LeaseError("not connected")
        fields = page.eval_on_selector_all(
            "input,textarea,select",
            "els => els.map(e => ({tag: e.tagName.toLowerCase(), name: e.name, type: e.type, value: e.value}))")
        headings = page.eval_on_selector_all(
            "h1,p", "els => els.slice(0,12).map(e => e.innerText.trim()).filter(Boolean)")
        return {"url": page.url, "title": page.title(), "headings": headings, "fields": fields}

    def prepare(self, path: str, body: Dict[str, Any], method: str = "POST") -> Dict[str, Any]:
        session = self.st["session"]
        if session is None:
            raise LeaseError("not connected")
        origin = session.spec["browser"]["allowed_origins"][0]
        before = ""
        page = self.st["page"]
        if page is not None:
            try:
                r = page.request.get(origin + path)
                before = r.text()[:400]
            except Exception:
                pass
        proposal = session.prepare(method, origin, path, body)
        self.receipt({"event": "prepare", "proposal_id": proposal.proposal_id,
                      "url": f"{origin}{path}", "method": method, "body": body,
                      "commits_left_after_commit": session.commits_left - 1})
        return {"proposal": proposal.as_dict(), "before": before,
                "commits_left": session.commits_left,
                "note": "Nothing sent yet. ruse_commit executes exactly this request, once."}

    def commit(self, proposal_id: str) -> Dict[str, Any]:
        session, page = self.st["session"], self.st["page"]
        if session is None or page is None:
            raise LeaseError("not connected")
        armed = session.armed
        if armed is None or armed.proposal_id != proposal_id:
            raise LeaseError("no such armed proposal (prepare first; "
                             "commit cannot invent its own request)")
        url = f"{armed.origin}{armed.path}"
        body_json = json.dumps(armed.body)
        resp = page.evaluate(
            """async ({url, method, body}) => {
                 try {
                   const r = await fetch(url, {method: method,
                        headers: {'Content-Type': 'application/json'}, body: body});
                   return {status: r.status, text: await r.text()};
                 } catch (e) { return {status: 0, text: String(e)}; }
               }""",
            {"url": url, "method": armed.method, "body": body_json})
        result = {"commit": resp, "commits_left": session.commits_left}
        # immediate verification read — via the record's read page
        w = session.spec["permissions"].get("write") or {}
        verify_path = w.get("verify_path") or (armed.path.replace("/api/", "/", 1)
                                               if "/api/" in armed.path else armed.path)
        try:
            after = page.request.get(f"{armed.origin}{verify_path}")
            after_text = after.text()[:400]
            result["after"] = after_text
            result["verified"] = (after.status == 200 and
                                  any(str(v) in after_text for v in armed.body.values()))
        except Exception as exc:
            result["after"] = f"verify read failed: {exc}"
            result["verified"] = False
        self.receipt({"event": "commit", "proposal_id": proposal_id, "url": url,
                      "status": resp.get("status"), "verified": result["verified"],
                      "commits_left": session.commits_left})
        return result

    def revoke(self) -> Dict[str, Any]:
        session = self.st["session"]
        if session is not None:
            session.revoke()
        if self.st["ctx"] is not None:
            try:
                self.st["ctx"].close()
            except Exception:
                pass
        self.st.update({"ctx": None, "page": None})
        self.st["enforce"] = False
        self.receipt({"event": "revoke"})
        return {"ok": True, "note": "lease revoked; armed proposals discarded; "
                                    "browser session closed"}

    def status(self) -> Dict[str, Any]:
        s = self.st["session"]
        if s is None:
            return {"active": False}
        return {"active": s.active(), "expired": s.expired(), "revoked": s.revoked,
                "commits_left": s.commits_left,
                "armed": s.armed.as_dict() if s.armed else None,
                "started": s.started, "ttl_seconds": s.ttl}

    def receipts(self, n: int = 20) -> list:
        return self.recent_receipts(n)

    def shutdown(self) -> None:
        if self.st["ctx"] is not None:
            try:
                self.st["ctx"].close()
            except Exception:
                pass
        if self.st["pw"] is not None:
            try:
                self.st["pw"].stop()
            except Exception:
                pass
