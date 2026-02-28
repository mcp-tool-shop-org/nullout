# NullOut Treatment Guide (v1.x)

## What NullOut does

NullOut detects and removes Windows filesystem entries that are difficult to manage
via normal Win32 tools: reserved device basenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9),
trailing dot/space names, and overlong paths.

NullOut runs as an MCP server over stdio JSON-RPC and requires explicit confirmation
tokens for deletion.

## What NullOut will never do (v1)

- Never deletes outside allowlisted roots (`NULLOUT_ROOTS`)
- Never accepts raw paths for destructive operations
- Never follows reparse points (deny_all policy)
- Never deletes non-empty directories (empty-only rule)
- Never performs rename-then-delete device-namespace tricks (`\\.\`)
- Never modifies ACLs or takes ownership
- Never deletes Alternate Data Streams (ADS)

## Configuration

Set allowlisted roots and token secret via environment variables:

| Variable | Required | Description |
|---|---|---|
| `NULLOUT_ROOTS` | Yes | Semicolon-separated list of absolute paths |
| `NULLOUT_TOKEN_SECRET` | Yes | Random secret for HMAC token signing |

Example (PowerShell):

```powershell
$env:NULLOUT_ROOTS = "C:\Users\me\Downloads;D:\Staging"
$env:NULLOUT_TOKEN_SECRET = (python -c "import secrets; print(secrets.token_hex(32))")
```

## Typical workflow

```
1) list_allowed_roots          → see what's scoped
2) scan_reserved_names         → find hazardous entries
3) plan_cleanup                → get per-finding confirmToken (TTL 5 min)
4) delete_entry                → execute with {findingId, confirmToken}
```

The host (Claude Code or other MCP client) drives this loop. Each `confirmToken` is
HMAC-signed, bound to the finding's identity (volumeSerial + fileId), strategy, and
expiration. Tokens cannot be reused across findings or after identity changes.

## Error codes and what to do

### E_IN_USE

Target is open/locked by another process.

**Next:** call `who_is_using(findingId)` for Restart Manager attribution. Close the
identified process, then retry `delete_entry` with a fresh plan.

#### who_is_using output

Each process entry contains:

| Field | Type | Description |
|---|---|---|
| `pid` | int | Process ID |
| `appName` | string | Application name (best available) |
| `serviceShortName` | string | Service short name (empty for non-services) |
| `type` | string | `main_window`, `other_window`, `service`, `explorer`, `console`, `critical`, `unknown`, or `unknown_<n>` for undocumented RM application types |
| `sessionId` | int | Terminal Services session ID |
| `restartable` | bool | Whether the process registered for restart |

**`type` is not a closed enum.** Windows may return undocumented application type
codes (e.g. `1000` on Windows 11). These are formatted as `unknown_<n>` and should
be treated as informational. Do not switch/match on type exhaustively.

**Trailing dot/space limitation:** For entries with `WIN_TRAILING_DOT_SPACE` hazard,
Restart Manager receives a Win32 path that gets normalized (trailing chars stripped).
RM may fail to find lockers for the exact on-disk entry. When this applies:

- `confidence` is downgraded to `medium` (with results) or `low` (without)
- A `limitations` note explains the constraint
- If RM returns empty, a secondary query with the normalized path name is attempted
  as a hint — results are labeled `"source": "normalized_path_hint"` and should be
  treated as non-authoritative

### E_ACCESS_DENIED / E_ELEVATION_REQUIRED

Permissions block deletion.

**Next:** retry from an elevated host/session. NullOut does not change ACLs.

### E_DIR_NOT_EMPTY

v1 deletes empty directories only.

**Next:** remove contents first (manually or via targeted scan + delete of children),
then retry.

### E_REPARSE_POLICY_BLOCKED

Target is a reparse point (symlink, junction, or mount point). Policy is `deny_all`.

**Next:** delete the link manually if intended. Future versions may support
configurable reparse policies.

### E_CHANGED_SINCE_SCAN

TOCTOU protection: the filesystem object's identity (volumeSerial + fileId) changed
between scan and delete.

**Next:** rescan and replan. Do not reuse old tokens.

### E_IO_ERROR / E_CORRUPT_METADATA

I/O error or corruption suspected (winerror 23, 1117, or 1392).

**Next:** stop retrying. Run `chkdsk` and storage diagnostics. Back up before
any further attempts.

### E_TRAVERSAL_REJECTED

Operation would escape the allowlisted root (path traversal detected).

**Next:** verify `NULLOUT_ROOTS` is correct. Use paths strictly within roots.

### E_ROOT_NOT_ALLOWED

The `rootId` is not in the current allowlisted roots.

**Next:** check `NULLOUT_ROOTS` and restart the server if roots changed.

### E_CONFIRM_TOKEN_INVALID

Token signature verification failed. Token may be corrupted, from a different server
instance, or bound to a different finding/strategy.

**Next:** call `plan_cleanup` again to get a fresh token.

### E_CONFIRM_TOKEN_EXPIRED

Token TTL (5 minutes) exceeded.

**Next:** call `plan_cleanup` again and execute promptly.

## Verification

Run the end-to-end shipcheck script:

```powershell
pwsh -File scripts/shipcheck.ps1
```

This starts the server, creates hazardous fixtures (reserved device name, trailing
dot/space directories, junction), and verifies scan→plan→delete for each invariant.

## Audit trail

All destructive attempts produce structured results including:
- `findingId`, `strategy`, `entryType`
- `telemetry.durationMs`, `telemetry.usedExtendedNamespace`
- Error responses include `code`, `message`, `details`, and `nextSteps`

The host is responsible for persisting these results. NullOut does not write to disk.
