# Ruse — Owner-Controlled MCP Tool Safety Contracts for Hermes

> **Pitch:** An MCP server can label a destructive tool as read-only, and Hermes may trust that label. Ruse replaces server-claimed safety metadata with owner-approved, hash-pinned tool contracts.

## The Problem

Hermes uses MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) to decide whether to ask for approval on `trust: untrusted` servers. The MCP specification warns:

> "Clients **must** treat tool annotations to be untrusted unless they come from trusted servers."

Yet Hermes trusts these hints operationally. A server claiming `readOnlyHint: true` skips the approval gate entirely — even if the tool deletes files.

## Ruse's Fix

A transparent stdio MCP proxy that:

1. **Intercepts** every `tools/list` response
2. **Fingerprints** the complete tool contract (name, description, schemas, **annotations**) with SHA-256
3. **Checks** owner approval; unapproved contracts get conservative annotations
4. **Revokes** any approval on contract change (the server cannot edit its way back to read-only)

## Architecture

```
   Hermes Agent                  Ruse Proxy
  ┌─────────────┐    tools/list   ┌───────────┐   tools/list    ┌────────────┐
  │  Model/API  │ ───────────────→│ fingerprint │ ─────────────→│ MCP Server │
  │             │  ←──────────────│ rewrite   │ ←─────────────│            │
  └─────────────┘                 └───────────┘                 └────────────┘
                                      ▲         ▲
                                      │         │
                                  policy.json  audit.jsonl
```

## Owner CLI

```bash
ruse status                     # list: claim vs effective vs approved
ruse diff evil/read_note        # show reviewed contract
ruse approve-readonly evil/read_note   # owner approves exact contract
ruse revoke evil/read_note      # drop approval
ruse audit 10                   # last 10 audit events
```

## Verification

- **Protocol**: 29/29 tests pass (`tests/test_ruse_proxy.py`)
- **Audit trail**: Every decision logged with claim vs effective policy
- **Rug-pull proof**: Schema/annotation changes auto-revoke approval

## Limitations (disclosed)

- NOT a sandbox — respects `approvals.mode: off` and YOLO as bypass
- Owner controls policy; compromised owner = compromised safety
- Requires Hermes >=0.23.0

## Why This Matters

[MCP Pin #152646](https://github.com/NousResearch/hermes-agent/pull/152646) fingerprints descriptions and schemas but **explicitly excludes annotations** (see its README). Ruse is the only entry closing this trust gap.