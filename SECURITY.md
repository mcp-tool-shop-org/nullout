# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

Email: **64996768+mcp-tool-shop@users.noreply.github.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Version affected
- Potential impact

### Response timeline

| Action | Target |
|--------|--------|
| Acknowledge report | 48 hours |
| Assess severity | 7 days |
| Release fix | 30 days |

## Scope

NullOut is an MCP server that scans for and removes "undeletable" files on Windows (reserved device names, trailing dots/spaces, overlong paths). It operates **locally only** via stdio JSON-RPC.

### Data touched

- **Filesystem metadata** — directory listings, file names, file IDs, volume serial numbers
- **Process metadata** — PIDs, app names, session IDs (via Restart Manager, read-only)
- **HMAC tokens** — short-lived confirmation tokens signed with a user-provided secret

### Data NOT touched

- **File contents** — NullOut never reads, writes, or inspects file contents
- **Network** — no outbound connections, no HTTP listeners, no telemetry
- **Credentials** — no passwords, API keys, or authentication tokens are read or stored
- **Registry** — no Windows registry access

### Permissions required

- Standard user permissions (no admin/elevation required)
- Read access to scan directories (configured via `NULLOUT_ROOTS`)
- Delete permission on target files (for `delete_entry` only)

### Threat model

NullOut defends against:

1. **Path traversal** — all operations confined to allowlisted roots; `..` components are resolved and rejected if they escape
2. **Reparse point escapes** — junctions, symlinks, and mount points are detected and never traversed or deleted (`deny_all` policy)
3. **TOCTOU races** — deletion tokens are HMAC-bound to volume serial + file ID; any change between scan and delete is rejected
4. **Token forgery** — HMAC-SHA256 with user-provided secret; tokens expire after 300 seconds
5. **Namespace tricks** — extended path prefix (`\\?\`) bypasses Win32 name parsing; all destructive operations use canonicalized paths
6. **Locked files** — Restart Manager attribution is read-only; NullOut never kills processes
7. **Non-empty directory deletion** — refused by policy; only empty directories can be deleted

### No telemetry

NullOut collects no usage data, analytics, or crash reports. No data leaves the machine.
