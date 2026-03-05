---
title: Configuration
description: Environment variables and policies.
sidebar:
  order: 4
---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `NULLOUT_ROOTS` | Yes | Semicolon-separated list of allowlisted scan directories |
| `NULLOUT_TOKEN_SECRET` | Yes | Random secret for HMAC-SHA256 token signing |

### NULLOUT_ROOTS

```bash
set NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Each path must be an absolute Windows path. NullOut will only scan and operate within these directories. Subdirectories are included automatically.

### NULLOUT_TOKEN_SECRET

```bash
set NULLOUT_TOKEN_SECRET=your-random-secret-here
```

Used to sign confirmation tokens. The secret should be random and kept private. Changing the secret invalidates all previously issued tokens.

## Policies

NullOut ships with fixed policies that cannot be overridden:

| Policy | Value | Why |
|--------|-------|-----|
| Reparse traversal | deny_all | Never follow junctions/symlinks/mounts |
| Directory deletion | empty-only | Non-empty directories are refused |
| Process killing | never | Attribution is read-only |
| Token expiry | per-session | Tokens are valid only for the current server session |

## Data scope

**Data touched:** filesystem metadata (names, file IDs, volume serials), process metadata (PIDs, app names via Restart Manager).

**Data NOT touched:** file contents, network, credentials, Windows registry.

**No telemetry** is collected or sent.

## What NullOut detects

NullOut scans for three categories of hazardous entries:

1. **Reserved device names** — `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`
2. **Trailing dots and spaces** — files ending with `.` or ` ` that Windows silently strips
3. **Overlong paths** — paths exceeding the Win32 MAX_PATH (260 characters)
