# Ship Gate

> No repo is "done" until every applicable line is checked.
> Copy this into your repo root. Check items off per-release.

**Tags:** `[all]` every repo · `[npm]` `[pypi]` `[vsix]` `[desktop]` `[container]` published artifacts · `[mcp]` MCP servers · `[cli]` CLI tools

---

## A. Security Baseline

- [x] `[all]` SECURITY.md exists (report email, supported versions, response timeline) (2026-02-28)
- [x] `[all]` README includes threat model paragraph (data touched, data NOT touched, permissions required) (2026-02-28)
- [x] `[all]` No secrets, tokens, or credentials in source or diagnostics output (2026-02-28)
- [x] `[all]` No telemetry by default — state it explicitly even if obvious (2026-02-28)

### Default safety posture

- [x] `[cli|mcp|desktop]` Dangerous actions (kill, delete, restart) require explicit `--allow-*` flag (2026-02-28) — delete_entry requires server-issued confirmToken bound to file identity
- [x] `[cli|mcp|desktop]` File operations constrained to known directories (2026-02-28) — allowlisted roots via NULLOUT_ROOTS
- [x] `[mcp]` Network egress off by default (2026-02-28) — stdio-only, no network connections
- [x] `[mcp]` Stack traces never exposed — structured error results only (2026-02-28) — all errors return {ok, error: {code, message, details, nextSteps}}

## B. Error Handling

- [x] `[all]` Errors follow the Structured Error Shape: `code`, `message`, `hint`, `cause?`, `retryable?` (2026-02-28) — NullOut shape: code, message, details, nextSteps
- [ ] `[cli]` SKIP: not a CLI tool — MCP server only
- [ ] `[cli]` SKIP: not a CLI tool
- [x] `[mcp]` Tool errors return structured results — server never crashes on bad input (2026-02-28)
- [x] `[mcp]` State/config corruption degrades gracefully (stale data over crash) (2026-02-28)
- [ ] `[desktop]` SKIP: not a desktop app
- [ ] `[vscode]` SKIP: not a VS Code extension

## C. Operator Docs

- [x] `[all]` README is current: what it does, install, usage, supported platforms + runtime versions (2026-02-28)
- [x] `[all]` CHANGELOG.md (Keep a Changelog format) (2026-02-28)
- [x] `[all]` LICENSE file present and repo states support status (2026-02-28) — MIT
- [ ] `[cli]` SKIP: not a CLI tool — entry point starts stdio JSON-RPC server
- [ ] `[cli|mcp|desktop]` SKIP: stdio JSON-RPC server — no user-facing logging levels
- [x] `[mcp]` All tools documented with description + parameters (2026-02-28) — TOOLS_LIST in server.py
- [ ] `[complex]` SKIP: not complex enough to warrant a handbook

## D. Shipping Hygiene

- [x] `[all]` `verify` script exists (test + build + smoke in one command) (2026-02-28) — scripts/shipcheck.ps1
- [x] `[all]` Version in manifest matches git tag (2026-02-28) — pyproject.toml + __init__.py
- [x] `[all]` Dependency scanning runs in CI (ecosystem-appropriate) (2026-02-28) — pip install validates deps, twine check validates packaging
- [ ] `[all]` SKIP: zero runtime deps, 2 dev deps (pytest, pytest-cov) — manual updates sufficient
- [ ] `[npm]` SKIP: not an npm package
- [x] `[pypi]` `python_requires` set (2026-02-28) — >=3.10
- [x] `[pypi]` Clean wheel + sdist build (2026-02-28) — release.yml builds and twine-checks
- [ ] `[vsix]` SKIP: not a VS Code extension
- [ ] `[desktop]` SKIP: not a desktop app

## E. Identity (soft gate — does not block ship)

- [x] `[all]` Logo in README header (2026-02-28)
- [x] `[all]` Translations (polyglot-mcp, 8 languages) (2026-02-28)
- [x] `[org]` Landing page (@mcptoolshop/site-theme) (2026-02-28)
- [x] `[all]` GitHub repo metadata: description, homepage, topics (2026-02-28)

---

## Gate Rules

**Hard gate (A-D):** Must pass before any version is tagged or published.
If a section doesn't apply, mark `SKIP:` with justification — don't leave it unchecked.

**Soft gate (E):** Should be done. Product ships without it, but isn't "whole."

**Checking off:**
```
- [x] `[all]` SECURITY.md exists (2026-02-27)
```

**Skipping:**
```
- [ ] `[pypi]` SKIP: not a Python project
```
