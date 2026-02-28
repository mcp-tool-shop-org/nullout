<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.zh.md">中文</a> | <a href="README.es.md">Español</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

MCP server that finds and safely removes "undeletable" files on Windows.

Windows reserves device names like `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, and `LPT1`-`LPT9` at the Win32 layer. Files with these names can exist on NTFS (created via WSL, Linux tools, or low-level APIs) but become impossible to rename, move, or delete through Explorer or normal shell commands.

NullOut scans for these hazardous entries and removes them safely using the `\\?\` extended path namespace, with a two-phase confirmation workflow designed for MCP hosts.

## How it works

1. **Scan** an allowlisted directory for reserved-name collisions, trailing dots/spaces, and overlong paths
2. **Plan** the cleanup — NullOut generates a per-entry confirmation token bound to the file's identity (volume serial + file ID)
3. **Delete** with the token — NullOut re-verifies the file hasn't changed (TOCTOU protection) before removing it via extended namespace

## Safety model

- **Allowlisted roots only** — operations are confined to directories you explicitly configure
- **No raw paths in destructive calls** — delete accepts only server-issued finding IDs + confirmation tokens
- **deny_all reparse policy** — junctions, symlinks, and mount points are never traversed or deleted
- **File identity binding** — tokens are HMAC-signed and bound to volume serial + file ID; any change between scan and delete is rejected
- **Empty-only directories** — v1 refuses to delete non-empty directories
- **Structured errors** — every failure returns a machine-readable code with next-step suggestions

## MCP tools

| Tool | Type | Purpose |
|------|------|---------|
| `list_allowed_roots` | read-only | Show configured scan roots |
| `scan_reserved_names` | read-only | Find hazardous entries in a root |
| `get_finding` | read-only | Get full details for a finding |
| `plan_cleanup` | read-only | Generate deletion plan with confirmation tokens |
| `delete_entry` | destructive | Delete a file or empty directory (requires token) |
| `who_is_using` | read-only | Identify processes locking a file (Restart Manager) |
| `get_server_info` | read-only | Server metadata, policies, and capabilities |

## Configuration

Set allowlisted roots via environment variable:

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Token signing secret (generate a random value):

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## Threat model

NullOut defends against:

- **Destructive misuse** — delete requires a server-issued confirmation token; no raw paths accepted
- **Path traversal** — all operations confined to allowlisted roots; `..` escapes are resolved and rejected
- **Reparse point escapes** — junctions, symlinks, and mount points are never traversed or deleted (`deny_all`)
- **TOCTOU races** — tokens are HMAC-bound to volume serial + file ID; any identity change between scan and delete is rejected
- **Namespace tricks** — destructive operations use `\\?\` extended path prefix to bypass Win32 name parsing
- **Locked files** — Restart Manager attribution is read-only; NullOut never kills processes
- **Non-empty directories** — refused by policy; only empty directories can be deleted

**Data touched:** filesystem metadata (names, file IDs, volume serials), process metadata (PIDs, app names via Restart Manager).
**Data NOT touched:** file contents, network, credentials, Windows registry.
**No telemetry** is collected or sent.

## Requirements

- Windows 10/11
- Python 3.10+

---

Built by <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a>
