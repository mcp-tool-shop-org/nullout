# NullOut

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

NullOut defends against: destructive misuse/overreach, path traversal/namespace tricks, reparse point escapes, TOCTOU races, and locked/corrupted file scenarios. See the spec for full details.

## Requirements

- Windows 10/11
- Python 3.10+

---

Built by [MCP Tool Shop](https://mcp-tool-shop.github.io/)
