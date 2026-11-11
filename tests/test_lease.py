#!/usr/bin/env python3
"""Ruse lease decision-matrix tests — the proof the boundary holds.

Every case maps to the submission evidence table: what the owner granted
is allowed; everything else is refused BEFORE reaching the application.
Pure logic, no browser, no network. Run: python3 tests/test_lease.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lease import LeaseSession, LeaseError, load_lease, validate_lease  # noqa: E402

ORIGIN = "http://127.0.0.1:8710"
PASS, FAIL = 0, 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} — {detail}")


def fresh() -> LeaseSession:
    return LeaseSession(load_lease(str(ROOT / "leases" / "crm.json")))


def test_lease_file():
    l = load_lease(str(ROOT / "leases" / "crm.json"))
    check("demo lease validates", True)
    validate_lease(l)
    for bad, why in [
        ({}, "empty"),
        ({"lease": {"ttl_seconds": -1, "max_commits": 1}, "browser": {"allowed_origins": ["http://x"]}}, "negative ttl"),
        ({"lease": {"ttl_seconds": 5, "max_commits": 1}, "browser": {"allowed_origins": ["127.0.0.1:8710"]}}, "origin missing scheme"),
        ({"lease": {"ttl_seconds": 5, "max_commits": 1}, "browser": {"allowed_origins": ["http://x"]},
          "permissions": {"write": {"method": "GET", "path": "/x", "fields": {}}}}, "write method GET"),
        ({"lease": {"ttl_seconds": 5, "max_commits": 1}, "browser": {"allowed_origins": ["http://x"]},
          "permissions": {"write": {"method": "POST", "path": "/x", "fields": {"status": {}}}}}, "field lacks allowed_values"),
    ]:
        try:
            validate_lease(bad)
            check(f"rejects {why}", False, "accepted a malformed lease")
        except LeaseError:
            check(f"rejects {why}", True)


def test_reads():
    s = fresh()
    check("allowed read forwarded", s.decide("GET", f"{ORIGIN}/contacts/123").allowed)
    check("customer list read allowed", s.decide("GET", f"{ORIGIN}/contacts").allowed)
    d = s.decide("GET", f"{ORIGIN}/contacts/999")
    check("wrong resource read denied", not d.allowed and d.rule == "lease.path", d.reason)
    d = s.decide("GET", "http://evil.example/contacts/123")
    check("cross-origin read denied", not d.allowed and d.rule == "lease.origin", d.reason)


def test_writes_never_spontaneous():
    s = fresh()
    d = s.decide("DELETE", f"{ORIGIN}/api/contacts/123")
    check("page-script DELETE denied", not d.allowed and d.rule in ("lease.denied", "commit.not_armed"), d.reason)
    d = s.decide("POST", f"{ORIGIN}/api/contacts/999", {"status": "deleted"})
    check("page-script write to 999 denied", not d.allowed, d.reason)
    check("no prepared commit armed", s.armed is None)


def test_prepare_matrix():
    s = fresh()
    try:
        s.prepare("POST", ORIGIN, "/contacts/999", {"status": "qualified"})
        check("prepare wrong resource refused", False, "accepted out-of-lease path")
    except LeaseError:
        check("prepare wrong resource refused", True)
    try:
        s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "deleted", "note": "x"})
        check("prepare extra field refused", False, "accepted unknown field")
    except LeaseError:
        check("prepare extra field refused", True)
    try:
        s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "deleted"})
        check("prepare unapproved value refused", False, "accepted 'deleted'")
    except LeaseError:
        check("prepare unapproved value refused", True)
    try:
        s.prepare("DELETE", ORIGIN, "/contacts/123", {})
        check("prepare DELETE refused", False, "accepted DELETE")
    except LeaseError:
        check("prepare DELETE refused", True)
    p = s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "qualified"})
    check("approved proposal armed", s.armed is not None and s.armed.proposal_id == p.proposal_id)
    # armed commit matches -> allowed exactly once
    d = s.decide("POST", f"{ORIGIN}/api/contacts/123", {"status": "qualified"})
    check("armed commit allowed", d.allowed, d.reason)
    s.consume_commit()
    d = s.decide("POST", f"{ORIGIN}/api/contacts/123", {"status": "qualified"})
    check("commit replay denied (one-time)",
          not d.allowed and d.rule in ("commit.budget", "commit.not_armed"), d.reason)
    check("armed proposal discarded after use", s.armed is None)


def test_tampered_commit():
    s = fresh()
    s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "qualified"})
    d = s.decide("POST", f"{ORIGIN}/api/contacts/123", {"status": "qualified", "admin": True})
    check("commit with extra key denied", not d.allowed and d.rule == "commit.body_mismatch", d.reason)
    d = s.decide("POST", f"{ORIGIN}/api/contacts/123", {})
    check("commit with missing key denied", not d.allowed, d.reason)
    d = s.decide("POST", f"{ORIGIN}/contacts/999", {"status": "qualified"})
    check("commit to wrong path denied", not d.allowed and d.rule == "commit.mismatch", d.reason)
    d = s.decide("PUT", f"{ORIGIN}/contacts/123", {"status": "qualified"})
    check("commit with wrong method denied", not d.allowed, d.reason)


def test_denied_list_and_expiry():
    s = fresh()
    s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "qualified"})
    d = s.decide("DELETE", f"{ORIGIN}/api/contacts/123")
    check("DELETE stays denied even while armed", not d.allowed and d.rule == "lease.denied", d.reason)
    s2 = LeaseSession(load_lease(str(ROOT / "leases" / "crm.json")), now=time.time() - 301)
    d = s2.decide("GET", f"{ORIGIN}/contacts/123")
    check("expired lease denies reads", not d.allowed and d.rule == "lease.expired", d.reason)
    s3 = fresh()
    s3.revoke()
    check("revoked lease denies everything", not s3.decide("GET", f"{ORIGIN}/contacts/123").allowed)
    check("revoked lease denies writes", not s3.decide("POST", f"{ORIGIN}/contacts/123", {}).allowed)


def test_zero_commit_budget():
    spec = load_lease(str(ROOT / "leases" / "crm.json"))
    spec["lease"]["max_commits"] = 0
    s = LeaseSession(spec)
    try:
        s.prepare("POST", ORIGIN, "/api/contacts/123", {"status": "qualified"})
        check("zero-budget lease refuses prepare", False, "armed a commit with budget 0")
    except LeaseError:
        check("zero-budget lease refuses prepare", True)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        os.chdir(td)
    print("lease decision-matrix tests:")
    test_lease_file()
    test_reads()
    test_writes_never_spontaneous()
    test_prepare_matrix()
    test_tampered_commit()
    test_denied_list_and_expiry()
    test_zero_commit_budget()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
