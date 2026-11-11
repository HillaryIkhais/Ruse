#!/usr/bin/env python3
"""Ruse lease engine — the pure decision layer.

A lease is a temporary, owner-granted grant of browser authority:

    lease:    name, ttl_seconds, max_commits
    browser:  allowed_origins, allowed_paths (GET navigations/reads)
    write:    the ONE write operation permitted (method, path, allowed
              body keys, per-field value constraints)
    denied:   explicit denial list (defence in depth)

`decide()` answers a single question for every outbound browser request:
"does the active lease authorise THIS request?" It is pure and
side-effect-free so the whole matrix can be unit-tested without a browser.

Design invariant enforced here, not in the browser:
  * GETs must be inside allowed_origins + allowed_paths.
  * Non-GETs are allowed ONLY while a prepared commit is armed AND the
    request matches the armed proposal exactly AND the commit budget
    remains. Nothing else mutates.
  * An expired, revoked, or missing lease denies everything (fail closed).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

READ = "GET"


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "rule": self.rule, **self.detail}


@dataclass
class Proposal:
    """A prepared write. The exact request is frozen here; commit can
    only execute this, and only once."""
    proposal_id: str
    method: str
    origin: str
    path: str
    body: Dict[str, Any]
    armed_at: float

    def as_dict(self) -> Dict[str, Any]:
        return {"proposal_id": self.proposal_id, "method": self.method,
                "url": f"{self.origin}{self.path}", "body": self.body}


class LeaseError(Exception):
    pass


def _origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


def _path_matches(allowed: List[str], path: str) -> bool:
    """Exact grant by default; an entry ending in '/' grants its subtree.

    Scope precision is deliberate: '/contacts' grants only the list page,
    not every record under it — '/contacts/' would grant the subtree.
    """
    for a in allowed:
        if a.endswith("/") and len(a) > 1:  # '/api/' subtree; bare '/' stays exact
            if path.startswith(a):
                return True
        elif path == a:
            return True
    return False


def load_lease(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        lease = json.load(fh)
    validate_lease(lease)
    return lease


def validate_lease(lease: Dict[str, Any]) -> None:
    try:
        for key in ("lease", "browser", "permissions"):
            if key not in lease:
                raise LeaseError(f"lease missing section: {key}")
        l = lease["lease"]
        if not isinstance(l.get("ttl_seconds"), (int, float)) or l["ttl_seconds"] <= 0:
            raise LeaseError("lease.ttl_seconds must be a positive number")
        if not isinstance(l.get("max_commits"), int) or l["max_commits"] < 0:
            raise LeaseError("lease.max_commits must be a non-negative integer")
        b = lease["browser"]
        if not b.get("allowed_origins"):
            raise LeaseError("browser.allowed_origins must not be empty")
        for o in b["allowed_origins"]:
            if "://" not in o:
                raise LeaseError(f"allowed_origin is not scheme://host[:port]: {o}")
        w = lease["permissions"].get("write")
        if w is not None:
            if "method" not in w or "path" not in w:
                raise LeaseError("permissions.write needs method and path")
            if w["method"] == READ:
                raise LeaseError("permissions.write method must not be GET")
            for key, constraint in (w.get("fields") or {}).items():
                if "allowed_values" not in constraint:
                    raise LeaseError(f"write.fields.{key} lacks allowed_values")
    except KeyError as exc:
        raise LeaseError(f"lease missing key: {exc}") from exc


class LeaseSession:
    """Runtime state of one lease: expiry, commit budget, armed proposal."""

    def __init__(self, lease: Dict[str, Any], now: Optional[float] = None):
        validate_lease(lease)
        self.spec = lease
        self.started = now if now is not None else time.time()
        self.ttl = float(lease["lease"]["ttl_seconds"])
        self.commits_left = int(lease["lease"]["max_commits"])
        self.revoked = False
        self.armed: Optional[Proposal] = None
        self.total_commits_allowed = 0

    # -- lifecycle -------------------------------------------------------
    def expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) > self.started + self.ttl

    def revoke(self) -> None:
        self.revoked = True
        self.armed = None

    def active(self, now: Optional[float] = None) -> bool:
        return not self.revoked and not self.expired(now)

    # -- enforcement -----------------------------------------------------
    def decide(self, method: str, url: str,
               body: Optional[Dict[str, Any]] = None,
               now: Optional[float] = None) -> Decision:
        """Authorise one outbound browser request. Fail closed."""
        method = (method or "").upper()
        origin, path = _origin_of(url), _path_of(url)

        if not self.active(now):
            if self.revoked:
                return Decision(False, "lease revoked by owner", "lease.revoked")
            return Decision(False, "lease expired (ttl_seconds reached)", "lease.expired")

        origins = self.spec["browser"]["allowed_origins"]
        if origin not in origins:
            return Decision(False, f"origin {origin} is not in the lease "
                                  f"({', '.join(origins)})", "lease.origin")

        if method == READ:
            if _path_matches(self.spec["browser"]["allowed_paths"], path):
                return Decision(True, "read inside lease scope", "lease.read",
                                {"origin": origin, "path": path})
            return Decision(False, f"GET {path} is outside allowed_paths", "lease.path")

        # --- every mutating method from here on --------------------------
        denied = self.spec["permissions"].get("denied") or []
        if method in denied:
            return Decision(False, f"method {method} is explicitly denied by the lease",
                            "lease.denied")

        if self.armed is None:
            return Decision(False, "no prepared commit is armed; the lease permits "
                                  "no spontaneous writes", "commit.not_armed")

        p = self.armed
        if p.method != method or p.origin != origin or p.path != path:
            return Decision(False, f"request does not match the prepared commit "
                                  f"({p.method} {p.origin}{p.path})", "commit.mismatch")
        if body is not None:
            extra = set(body) - set(p.body)
            missing = set(p.body) - set(body)
            if extra or missing:
                return Decision(False, "body does not match the prepared commit",
                                "commit.body_mismatch",
                                {"unexpected_keys": sorted(extra), "missing_keys": sorted(missing)})
        if self.commits_left <= 0:
            return Decision(False, "commit budget exhausted (max_commits reached)",
                            "commit.budget")
        return Decision(True, "prepared commit authorised", "commit.allowed",
                        {"proposal_id": p.proposal_id})

    def consume_commit(self) -> None:
        if self.armed is None:
            raise LeaseError("no armed proposal")
        if self.commits_left <= 0:
            raise LeaseError("commit budget exhausted")
        self.commits_left -= 1
        self.total_commits_allowed += 1
        self.armed = None  # one-time use, always

    # -- proposal preparation --------------------------------------------
    def prepare(self, method: str, origin: str, path: str,
                body: Dict[str, Any]) -> Proposal:
        """Owner-visible pre-execution check of a proposed write against the
        lease. Raises LeaseError with a reason the model can show the owner."""
        if not self.active():
            raise LeaseError("lease is not active (expired or revoked)")
        if origin not in self.spec["browser"]["allowed_origins"]:
            raise LeaseError(f"origin {origin} is not in the lease")
        w = self.spec["permissions"].get("write")
        if not w:
            raise LeaseError("the lease grants no write permission")
        if method.upper() != w["method"].upper() or path != w["path"]:
            raise LeaseError(f"only {w['method']} {w['path']} may be prepared "
                             f"(got {method} {path})")
        allowed_keys = set((w.get("fields") or {}).keys())
        keys = set(body.keys())
        if allowed_keys and keys - allowed_keys:
            raise LeaseError(f"body has fields outside the lease: "
                             f"{sorted(keys - allowed_keys)}")
        for key, constraint in (w.get("fields") or {}).items():
            if key in body:
                vals = constraint["allowed_values"]
                if body[key] not in vals:
                    raise LeaseError(f"field '{key}' must be one of {vals} "
                                     f"(got {body[key]!r})")
        if self.commits_left <= 0:
            raise LeaseError("commit budget exhausted (max_commits reached)")
        proposal = Proposal(proposal_id=uuid.uuid4().hex[:12], method=method.upper(),
                            origin=origin, path=path, body=dict(body),
                            armed_at=time.time())
        self.armed = proposal
        return proposal

    def unarm(self) -> None:
        self.armed = None
