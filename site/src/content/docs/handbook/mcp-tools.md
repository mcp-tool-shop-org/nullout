---
title: MCP Tools
description: The 7 tools and the two-phase workflow.
sidebar:
  order: 2
---

NullOut exposes 7 MCP tools — 6 read-only and 1 destructive.

## Tool reference

| Tool | Type | Purpose |
|------|------|---------|
| `list_allowed_roots` | read-only | Show configured scan roots |
| `scan_reserved_names` | read-only | Find hazardous entries in a root |
| `get_finding` | read-only | Get full details for a finding |
| `plan_cleanup` | read-only | Generate deletion plan with confirmation tokens |
| `delete_entry` | destructive | Delete a file or empty directory (requires token) |
| `who_is_using` | read-only | Identify processes locking a file (Restart Manager) |
| `get_server_info` | read-only | Server metadata, policies, and capabilities |

## Typical workflow

### Step 1: List roots

```
list_allowed_roots
```

Returns the directories NullOut is configured to scan. If a directory isn't listed, it's off-limits.

### Step 2: Scan

```
scan_reserved_names({ root: "C:\\Users\\me\\Downloads" })
```

Returns a list of findings — files with reserved device names, trailing dots/spaces, or overlong paths. Each finding gets a unique ID.

### Step 3: Inspect

```
get_finding({ finding_id: "abc123" })
```

Returns full details: filename, path, why it's hazardous, file size, timestamps.

### Step 4: Plan

```
plan_cleanup({ finding_ids: ["abc123", "def456"] })
```

Generates an HMAC-signed confirmation token for each finding. Tokens are bound to the file's volume serial number and file ID — if the file changes between plan and delete, the token becomes invalid.

### Step 5: Delete

```
delete_entry({ finding_id: "abc123", token: "..." })
```

Re-verifies the file identity against the token, then removes it via the `\\?\` extended path namespace. Refuses to delete non-empty directories.

## Process attribution

```
who_is_using({ path: "C:\\Users\\me\\Downloads\\CON" })
```

Uses the Windows Restart Manager to identify which processes have a lock on the file. This is read-only — NullOut never kills processes.
