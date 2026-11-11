#!/usr/bin/env python3
"""Ruse end-to-end test — real Chrome, real CRM fixture, real attacks.

The CRM fixture's server-side audit log is the judge here: if a blocked
request never appears in it, it never reached the application. Run:
    python3 tests/test_e2e.py
Requires: playwright + Google Chrome (channel='chrome').
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker import Broker  # noqa: E402
from lease import LeaseError  # noqa: E402

PORT = 8710
ORIGIN = f"http://127.0.0.1:{PORT}"
PASS, FAIL = 0, 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} — {detail}")


def crm_audit() -> dict:
    with urllib.request.urlopen(f"{ORIGIN}/_audit", timeout=5) as r:
        return json.loads(r.read())


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ruse-e2e-"))
    audit_file = tmp / "crm-audit.jsonl"
    data_dir = tmp / "data"
    data_dir.mkdir()

    env = dict(os.environ, CRM_PORT=str(PORT), CRM_AUDIT=str(audit_file))
    fixture = subprocess.Popen([sys.executable, str(ROOT / "fixtures" / "crm_fixture.py")],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for the fixture to listen
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{ORIGIN}/", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("fixture failed to start")
            return 1

        creds = tmp / "credentials.json"
        creds.write_text(json.dumps({"user": "owner", "pass": "hunter2"}))
        broker = Broker(str(data_dir))

        print("lifecycle:")
        conn = broker._invoke("connect", str(ROOT / "leases" / "crm.json"), str(creds))
        check("connect under lease", conn.get("ok") is True, str(conn))
        check("commit budget granted", conn.get("commits_left") == 1, str(conn))

        print("governed reads:")
        nav = broker._invoke("navigate", "/contacts/123")
        check("navigate to allowed record", f"{ORIGIN}/contacts/123" == nav.get("url"), str(nav))
        info = broker._invoke("inspect")
        check("inspect sees the record", any("Customer 123" in h for h in info["headings"]), str(info))
        try:
            broker._invoke("navigate", "/contacts/999")
            check("navigate to forbidden record refused", False, "allowed /contacts/999")
        except LeaseError:
            check("navigate to forbidden record refused", True)

        print("hostile page (server never sees the attacks):")
        # the page's own script attempts DELETE 123, write 999, and exfil
        broker._invoke("navigate", "/contacts/123?attack=1")
        deadline = time.time() + 10
        title = ""
        while time.time() < deadline:
            title = broker._invoke("inspect").get("title", "")
            if title.startswith("ATTACKS:"):
                break
            time.sleep(0.2)
        check("page script executed", title.startswith("ATTACKS:"), title)
        check("all three attacks failed from the page's view",
              title.count(":BLOCKED") == 3 or ("HTTP" not in title and title.count(":") == 4), title)
        audit = crm_audit()
        check("DELETE /contacts/123 never reached the CRM",
              "123" not in audit["deletes"], json.dumps(audit["deletes"]))
        check("write to /contacts/999 never reached the CRM",
              "999" not in audit["updates"], json.dumps(audit["updates"]))
        check("CRM processed no mutating requests during the attack",
              not audit["updates"] and not audit["deletes"], json.dumps(audit))

        print("owner-approved write:")
        prop = broker._invoke("prepare", "/api/contacts/123", {"status": "qualified"})
        pid = prop["proposal"]["proposal_id"]
        check("prepare arms one frozen proposal", bool(pid), str(prop))
        check("nothing sent at prepare time", not crm_audit()["updates"], "server saw a write")
        res = broker._invoke("commit", pid)
        check("commit executed", res["commit"].get("status") == 200, str(res))
        check("post-commit verification read confirms state",
              res.get("verified") is True, str(res.get("after", ""))[:120])
        audit = crm_audit()
        check("CRM received exactly the approved update",
              audit["updates"].get("123") == 1 and "999" not in audit["updates"],
              json.dumps(audit["updates"]))

        print("budget and revocation:")
        try:
            broker._invoke("commit", pid)
            check("replayed commit refused", False, "second commit succeeded")
        except LeaseError:
            check("replayed commit refused", True)
        check("server still saw exactly one write", crm_audit()["updates"].get("123") == 1)
        try:
            broker._invoke("prepare", "/api/contacts/123", {"status": "qualified"})
            check("prepare after budget exhaustion refused", False, "budget not enforced")
        except LeaseError:
            check("prepare after budget exhaustion refused", True)

        broker._invoke("revoke")
        try:
            broker._invoke("navigate", "/contacts/123")
            check("post-revocation operation refused", False, "lease survived revoke")
        except LeaseError:
            check("post-revocation operation refused", True)

        receipts = broker._invoke("receipts", 100)
        denies = [r for r in receipts if r.get("event") == "deny"]
        check("receipts record the denials", len(denies) >= 3, f"{len(denies)} denials")
        check("receipts record the commit", any(r.get("event") == "commit"
                                                and r.get("verified") for r in receipts))
        broker._invoke("shutdown")
        print(f"\ndata dir: {tmp}")
    finally:
        fixture.terminate()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
