---
title: Getting Started
description: Install NullOut, configure roots, and run your first scan.
sidebar:
  order: 1
---

## Install

Install from PyPI:

```bash
pip install nullout-mcp
```

## Configure

NullOut requires two environment variables:

### Allowlisted roots

Set the directories NullOut is allowed to scan:

```bash
set NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

NullOut will refuse to operate outside these directories. This is a hard confinement boundary — no exceptions.

### Token signing secret

Generate a random secret for HMAC token signing:

```bash
set NULLOUT_TOKEN_SECRET=your-random-secret-here
```

Tokens bind deletion confirmations to specific file identities. Without a secret, the server won't start.

## Run

Start the MCP server:

```bash
nullout-mcp
```

Or register it in your MCP host configuration for automatic startup.

## Requirements

- Windows 10 or 11
- Python 3.10 or later

## The workflow

NullOut uses a deliberate three-step process:

1. **Scan** — find hazardous entries in an allowlisted directory
2. **Plan** — generate confirmation tokens bound to each file's identity
3. **Delete** — remove entries using the tokens (re-verifies identity first)

This two-phase confirmation prevents accidental deletions and race conditions.
