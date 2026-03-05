---
title: Handbook
description: Everything you need to know about NullOut.
sidebar:
  order: 0
---

Welcome to the NullOut handbook. This is the complete guide to finding and safely removing undeletable files on Windows.

## What's inside

- **[Getting Started](/nullout/handbook/getting-started/)** — Install, configure, and run your first scan
- **[MCP Tools](/nullout/handbook/mcp-tools/)** — The 7 tools and the two-phase workflow
- **[Safety Model](/nullout/handbook/safety-model/)** — How NullOut protects your filesystem
- **[Configuration](/nullout/handbook/configuration/)** — Environment variables and policies

## What is NullOut?

Windows reserves device names like `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, and `LPT1`-`LPT9` at the Win32 layer. Files with these names can exist on NTFS (created via WSL, Linux tools, or low-level APIs) but become impossible to rename, move, or delete through Explorer or normal shell commands.

NullOut is an MCP server that scans for these hazardous entries and removes them safely using the `\\?\` extended path namespace, with a two-phase confirmation workflow.

[Back to landing page](/nullout/)
