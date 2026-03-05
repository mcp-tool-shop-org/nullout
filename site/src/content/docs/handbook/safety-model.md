---
title: Safety Model
description: How NullOut protects your filesystem.
sidebar:
  order: 3
---

NullOut implements defense in depth for filesystem operations. Every layer is designed to prevent accidental damage.

## Allowlisted roots

All operations are confined to directories explicitly configured via `NULLOUT_ROOTS`. Path traversal attempts using `..` are resolved and rejected. There is no way to operate outside the configured roots.

## No raw paths in destructive calls

The `delete_entry` tool does not accept file paths. It accepts only server-issued finding IDs paired with confirmation tokens. This prevents any direct path-based deletion.

## Reparse deny-all policy

Junctions, symlinks, and mount points are detected and never traversed or deleted. This prevents escaping the allowlisted root through filesystem redirections.

## File identity binding

Confirmation tokens are HMAC-SHA256 signed and bound to two immutable identifiers:

- **Volume serial number** — identifies the physical disk
- **File ID** — the NTFS master file table entry

If either changes between scan and delete (because the file was replaced, moved, or modified), the token is rejected. This eliminates TOCTOU (time-of-check-to-time-of-use) race conditions.

## Empty-only directories

NullOut refuses to delete non-empty directories. Only files and empty directories can be removed.

## Structured errors

Every failure returns a machine-readable error code with:

- What went wrong
- Why it was rejected
- What to do next

No raw stack traces are exposed through the MCP interface.

## Threat summary

| Threat | Defense |
|--------|---------|
| Destructive misuse | Token-based confirmation, no raw paths |
| Path traversal | Root confinement, `..` resolution and rejection |
| Reparse escapes | deny_all policy on junctions/symlinks/mounts |
| TOCTOU races | HMAC-bound volume serial + file ID tokens |
| Namespace tricks | `\\?\` extended path prefix for safe operations |
| Locked files | Read-only attribution, never kills processes |
| Non-empty dirs | Refused by policy |
