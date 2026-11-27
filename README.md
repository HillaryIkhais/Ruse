# Ruse — Bounded Browser Authority for Hermes

> **Your browser. Your permissions. Your agent.**
> Ruse grants Hermes a temporary, owner-approved capability lease over a dedicated
> authenticated browser profile — and enforces that lease at the browser's network
> boundary. Requests outside the lease never reach the application.

Hermes can drive a real browser with your logins. That is powerful — and it means
an agent can reach everything the account can, not just what you intended for the
task. Ruse closes that gap with a new primitive: **the browser capability lease**.

## The primitive: a capability lease

A lease is a small, owner-authored JSON grant with six dimensions:

| Dimension | What the lease fixes |
|---|---|
| Identity | a dedicated browser profile (`ruse-crm`), never your everyday profile |
| Origin | exactly which sites the browser may talk to |
| Resource | which pages/records are readable (`/contacts/123`, *not* `/contacts/999`) |
| Action | the **one** write operation permitted (method + path + allowed fields) |
| Arguments | which body fields may appear, and which values are allowed |
| Lifetime | TTL, a commit budget (`max_commits`), and instant revocation |

```json
{
  "lease": {"name": "update-customer-123", "ttl_seconds": 300, "max_commits": 1},
  "browser": {
    "profile": "ruse-crm",
    "allowed_origins": ["http://127.0.0.1:8710"],
    "allowed_paths": ["/", "/login", "/contacts", "/contacts/123"]
  },
  "permissions": {
    "write": {
      "method": "POST",
      "path": "/api/contacts/123",
      "fields": {"status": {"allowed_values": ["new", "qualified"]}}
    },
    "denied": ["DELETE", "PUT", "PATCH"]
  }
}
```

Path grants are exact: `/contacts` authorises only the list page — a trailing
slash (`/contacts/`) is what would grant the whole subtree.

## Enforcement architecture

The model never receives a browser it can drive freely. It receives ten
structured tools, and the actual browser lives inside the Ruse broker:

```
Hermes agent ──structured tools──▶ Ruse broker (lease engine + Playwright)
                                        │  every outbound request is decided:
                                        │  navigation, form submit, fetch, XHR
                                        ▼
                        authenticated dedicated profile ──▶ application
                                        ▲
                    denied requests are ABORTED at the network boundary
```

* **No arbitrary code surface.** There is no `browser_exec`, no JS evaluation, no
  raw CDP tool. Governed authority is expressed only as connect → inspect →
  navigate → fill → prepare → commit → verify → revoke.
* **Credential-free lease selection.** `ruse_connect` accepts only a plain lease
  name (`[A-Za-z0-9_-]{1,64}`) and verifies with `realpath` that the resolved
  file stays inside the leases directory. `../x` and absolute paths are refused.
* **Secrets via Hermes, not plaintext files.** The login password is read from
  `agent.secret_scope.get_secret("RUSE_CRM_PASSWORD")`; there is no
  `credentials.json` in the plugin data dir. Login selectors and the username
  are owner-authored in the lease's `browser.login` block. `ruse_inspect` blanks
  password-field values before returning fields to the model.
* **Preparation is not execution.** `ruse_prepare` freezes the exact request
  (method, path, body) into a one-time proposal. `ruse_commit` can execute only
  that frozen request — arguments cannot be changed at commit time, and the
  commit is consumed after one use.
* **Fail closed.** No lease, expired lease, revoked lease, or missing broker →
  every request is refused. Nothing falls back to an unrestricted browser.
* **The boundary is the network, not the prompt.** A page's own script, a form
  submission, and page fetch/XHR all pass the same decision function. Redirects
  are only partly covered by Playwright — see the disclosure below.
* **Body values, not just keys.** The commit body must match the frozen proposal
  exactly (keys *and* values). Same-key/different-value requests are denied.
* **No model-controlled paths.** The model selects a lease by name only; it
  cannot choose arbitrary local files for leases, credentials, or data dirs.

## Honest enforcement boundary disclosures

Playwright's `page.route()` does not intercept every possible browser egress path.
Ruse mitigates the known gaps, but they are disclosed here:

* **Context-level routes** are registered alongside page-level routes, covering
  popups and service workers that `page.route` alone misses.
* **WebSocket connections** are denied by default via `route_web_socket`.
* **Redirect chains:** Playwright's route handler fires only for the first URL
  in a redirect chain. A redirect to an unapproved origin after an approved
  first hop is a known gap — the lease's `allowed_origins` should list only
  origins the owner fully trusts.
* **First request of a popup** may not be intercepted by page routing; the
  context-level route is the mitigation.

## The proof standard

The demo fixture is a real local CRM with **server-side** audit logging and
counters. It knows nothing about Ruse — which is exactly what makes its log
evidence. `tests/test_e2e.py` (real Chrome, real fixture):

* a hostile page script attempts `DELETE /contacts/123`, writes customer 999,
  and exfiltrates to an external origin — **all three are blocked**, and the
  CRM's own log shows **zero mutating requests arrived**;
* the owner-approved write is prepared (nothing sent), committed once, and
  verified by re-reading the record;
* a replayed commit, a second commit, and any post-revocation operation are
  refused — the server still saw exactly one write;
* receipts record every allow and deny decision.

```bash
python3 tests/test_lease.py   # 32 decision-matrix tests, no browser needed
python3 tests/test_plugin_surface.py  # 45 plugin registration + containment tests
python3 tests/test_e2e.py     # 24 end-to-end tests against real Chrome
```

## Honest limitations

* **Not a sandbox.** Ruse governs the browser session it owns. If the same agent
  session also has unrestricted network tools (native browser toolset, shell,
  arbitrary HTTP), that is an unsafe deployment. Ruse does **not** detect or warn
  about co-enabled tools — the owner must avoid enabling those alongside Ruse.
* A compromised owner (or a lease the owner approves wrongly) is trusted.
  Ruse's guarantee is: *the agent cannot exceed the lease the owner granted*.
* Ruse verifies what the browser sent and what the app returned; it cannot
  guarantee an approved server is benevolent.
* stdio/local origins first; remote HTTP origins work for allowed-origins
  enforcement but profile pairing is designed for local dedicated profiles.
* Requires Hermes ≥ 0.23 and a Chromium with the `chrome` channel (Playwright).

## Install

```
hermes plugins install HillaryIkhais/Ruse
```

Then create a lease file under `plugin-data/ruse/leases/` (the directory follows
the active `HERMES_HOME` profile, or `plugins.entries.ruse.settings.data_dir`).
The model cannot create leases — placing a lease file is itself the owner's
grant. Leases are plain JSON with structure validation; there is no
cryptographic signature verification — the owner's act of placing the lease
file is the grant.

For auto-login, set the `RUSE_CRM_PASSWORD` secret in the Hermes profile
(Desktop Plugins settings, or the profile `.env`). Ruse resolves it through
`agent.secret_scope.get_secret` — it never reads a plaintext credential file.
If the secret is not set, auto-login is skipped and the owner signs in once in
the dedicated persistent browser profile. The username and the login selectors
are owner-configured under `browser.login` in the lease:

```json
"browser": {
  "allowed_origins": ["http://127.0.0.1:8710"],
  "allowed_paths": ["/", "/login", "/contacts/123"],
  "login": {
    "user": "owner",
    "path": "/",
    "user_selector": "input[name=user]",
    "pass_selector": "input[name=pass]",
    "submit_selector": "button"
  }
}
```
