#!/usr/bin/env python3
"""Ruse tool schemas — what the LLM sees.

The toolset is deliberately small and legible: connect, look, propose,
commit, verify, revoke. There is no tool that runs arbitrary Python,
evaluates JS, or sends raw CDP commands: governed authority is expressed
only through these structured operations.
"""

CONNECT = {
    "name": "ruse_connect",
    "description": (
        "Open a governed browser session under an owner-approved capability "
        "lease. The lease defines which origin, pages and ONE write operation "
        "you may use, and for how long. Call this before any other ruse_* "
        "tool. Returns the lease scope; anything outside it is blocked."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "lease": {"type": "string",
                      "description": "Lease name under the ruse data dir, e.g. 'crm'"},
            "lease_path": {"type": "string",
                           "description": "Full path to a lease .json file (overrides lease name lookup)"},
            "credentials_path": {"type": "string",
                                 "description": "Full path to credentials .json for the owner sign-in"},
            "data_dir": {"type": "string",
                         "description": "Ruse data directory (leases, receipts, profiles)"},
        },
        "required": ["lease"],
    },
}

INSPECT = {
    "name": "ruse_inspect",
    "description": (
        "Read the current governed page: URL, title, key text and form "
        "fields. Use this to understand the record you are allowed to work "
        "with. Read-only."
    ),
    "parameters": {"type": "object", "properties": {}},
}

NAVIGATE = {
    "name": "ruse_navigate",
    "description": (
        "Navigate the governed browser to a path inside the lease's allowed "
        "origins and pages. Paths outside the lease are refused."
    ),
    "parameters": {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "Path, e.g. /contacts/123"}},
        "required": ["path"],
    },
}

FILL = {
    "name": "ruse_fill",
    "description": (
        "Fill a form field on the current governed page. Submission is still "
        "gated: nothing is sent to the application unless the lease authorises "
        "it and the owner-approved commit flow is used."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "selector": {"type": "string", "description": "CSS selector, e.g. input[name=status]"},
            "value": {"type": "string"},
        },
        "required": ["selector", "value"],
    },
}

PREPARE = {
    "name": "ruse_prepare",
    "description": (
        "Propose the ONE write the lease permits (e.g. POST /contacts/123 with "
        "field/value). Nothing is sent. Ruse validates the proposal against "
        "the lease and returns a before/after summary for the owner to review. "
        "Returns a proposal_id used by ruse_commit."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Write path, e.g. /contacts/123"},
            "body": {"type": "object", "description": "Exact JSON body to propose"},
            "method": {"type": "string", "description": "HTTP method (lease defines the permitted one)"},
        },
        "required": ["path", "body"],
    },
}

COMMIT = {
    "name": "ruse_commit",
    "description": (
        "Execute the prepared proposal exactly once. The request is frozen at "
        "prepare time — arguments cannot be changed here. Verifies the "
        "application state afterwards and reports commits_left. Rejected if "
        "no proposal is armed or the commit budget is exhausted."
    ),
    "parameters": {
        "type": "object",
        "properties": {"proposal_id": {"type": "string"}},
        "required": ["proposal_id"],
    },
}

VERIFY = {
    "name": "ruse_verify",
    "description": "Re-read the governed resource and report its current observed state.",
    "parameters": {"type": "object", "properties": {}},
}

REVOKE = {
    "name": "ruse_revoke",
    "description": (
        "Invalidate the lease immediately: armed proposals are discarded and "
        "the browser session closes. Every later ruse_* operation is refused "
        "until a new lease is granted."
    ),
    "parameters": {"type": "object", "properties": {}},
}

STATUS = {
    "name": "ruse_status",
    "description": "Report the active lease: scope, expiry, commit budget, armed proposal.",
    "parameters": {"type": "object", "properties": {}},
}

RECEIPTS = {
    "name": "ruse_receipts",
    "description": "Recent enforcement receipts: every allowed and denied request the browser attempted.",
    "parameters": {
        "type": "object",
        "properties": {"n": {"type": "integer", "description": "How many (default 20)"}},
    },
}

ALL = [CONNECT, INSPECT, NAVIGATE, FILL, PREPARE, COMMIT, VERIFY, REVOKE, STATUS, RECEIPTS]
