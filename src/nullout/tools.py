"""MCP tool handlers: list_allowed_roots, scan, get_finding, plan, delete, who_is_using."""

from __future__ import annotations

import os
import time
from typing import Any

from nullout.config import Root, REPARSE_POLICY, TOKEN_TTL_SECONDS, STRATEGY_V1
from nullout.errors import err, ok
from nullout.hazards import detect_hazards, parse_basename, has_trailing_dot_or_space
from nullout.models import Finding
from nullout.restart_manager import who_is_using
from nullout.store import Store
from nullout.tokens import make_confirm_token, verify_confirm_token
from nullout.win_identity import get_identity
from nullout.win_paths import to_extended_path, is_under_root, is_reparse_point


def handle_list_allowed_roots(
    _args: dict[str, Any],
    roots: dict[str, Root],
) -> dict[str, Any]:
    """List all allowlisted roots with canonical paths and policy."""
    return ok({
        "roots": [
            {
                "rootId": r.root_id,
                "displayName": r.display_name,
                "path": r.path,
                "canonicalPath": to_extended_path(r.path),
                "reparsePolicy": REPARSE_POLICY,
            }
            for r in roots.values()
        ]
    })


def handle_scan_reserved_names(
    args: dict[str, Any],
    roots: dict[str, Root],
    store: Store,
) -> dict[str, Any]:
    """Scan an allowlisted root for reserved-name / Win32-hostile entries."""
    root_id = args["rootId"]
    recursive = args["recursive"]
    max_depth = args.get("maxDepth", 50)
    include_dirs = args["includeDirs"]

    if root_id not in roots:
        return err("E_ROOT_NOT_ALLOWED", "Unknown or not allowlisted root.", {"rootId": root_id})

    root = roots[root_id]
    root_abs = os.path.abspath(root.path)
    scan_id = store.new_id("scan")

    findings: list[dict[str, Any]] = []
    skipped_reparse = 0
    visited = 0

    def walk(current: str, depth: int) -> None:
        nonlocal skipped_reparse, visited
        if depth > max_depth:
            return
        try:
            with os.scandir(current) as it:
                for entry in it:
                    visited += 1
                    full = entry.path
                    name = entry.name
                    is_dir = entry.is_dir(follow_symlinks=False)

                    # deny_all: detect reparse points, don't traverse
                    if is_reparse_point(full):
                        skipped_reparse += 1
                        hazards = detect_hazards(name, len(to_extended_path(full)), is_reparse=True)
                        vol, fid = _safe_get_identity(full)
                        f = _make_finding(root_id, scan_id, root_abs, full, entry, hazards, vol, fid)
                        store.put_finding(f)
                        findings.append(f.to_dict())
                        continue

                    # Skip non-directory entries if includeDirs=False and it's a dir
                    if is_dir and not include_dirs:
                        if recursive:
                            walk(full, depth + 1)
                        continue

                    hazards = detect_hazards(name, len(to_extended_path(full)), is_reparse=False)

                    if hazards:
                        vol, fid = _safe_get_identity(full)
                        f = _make_finding(root_id, scan_id, root_abs, full, entry, hazards, vol, fid)
                        store.put_finding(f)
                        findings.append(f.to_dict())

                    if recursive and is_dir:
                        walk(full, depth + 1)
        except PermissionError:
            pass  # non-fatal: skip inaccessible directories

    walk(root_abs, 0)
    finding_ids = [f["findingId"] for f in findings]
    store.register_scan(scan_id, finding_ids)

    return ok({
        "scanId": scan_id,
        "rootId": root_id,
        "findings": findings,
        "stats": {
            "visited": visited,
            "flagged": len(findings),
            "skippedReparsePoints": skipped_reparse,
        },
    })


def handle_get_finding(
    args: dict[str, Any],
    store: Store,
) -> dict[str, Any]:
    """Return full details for a finding by ID."""
    finding_id = args["findingId"]
    finding = store.get_finding(finding_id)
    if not finding:
        return err("E_NOT_FOUND", "Finding not found.", {"findingId": finding_id})
    return ok({"finding": finding.to_dict()})


def handle_plan_cleanup(
    args: dict[str, Any],
    store: Store,
    token_secret: bytes,
) -> dict[str, Any]:
    """Generate a deletion plan with per-entry confirmation tokens."""
    finding_ids = args["findingIds"]
    actions = args["requestedActions"]

    if "DELETE" not in actions:
        return err("E_INVALID_REQUEST", "Only DELETE is supported in v1.", {})

    plan_id = store.new_id("plan")
    exp = time.time() + TOKEN_TTL_SECONDS
    entries: list[dict[str, Any]] = []

    for finding_id in finding_ids:
        finding = store.get_finding(finding_id)
        if not finding:
            return err("E_NOT_FOUND", "Finding not found.", {"findingId": finding_id})

        identity = finding.evidence.get("identity", {})
        token_payload = {
            "findingId": finding.findingId,
            "rootId": finding.rootId,
            "scanId": finding.scanId,
            "volumeSerial": identity.get("volumeSerial"),
            "fileId": identity.get("fileId"),
            "strategy": STRATEGY_V1,
            "reparsePolicy": REPARSE_POLICY,
            "exp": exp,
        }
        ctok = make_confirm_token(token_payload, token_secret)

        entries.append({
            "findingId": finding.findingId,
            "action": "DELETE",
            "strategy": STRATEGY_V1,
            "confirmToken": ctok,
            "bindings": {
                k: token_payload[k]
                for k in ["rootId", "scanId", "volumeSerial", "fileId", "strategy", "reparsePolicy"]
            },
            "riskNotes": [
                "Windows reserved-name / Win32-hostile entry; "
                "delete will use extended namespace."
            ],
        })

    return ok({
        "planId": plan_id,
        "expiresUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
        "entries": entries,
    })


def handle_delete_entry(
    args: dict[str, Any],
    roots: dict[str, Root],
    store: Store,
    token_secret: bytes,
) -> dict[str, Any]:
    """Delete a file or empty directory. Requires confirm token.

    Hard checks at delete time:
    1. Token valid + unexpired + bound to finding/strategy/identity
    2. Root confinement
    3. deny_all reparse policy
    4. Re-check identity (TOCTOU)
    5. If directory: ensure empty
    6. Delete using extended namespace
    """
    finding_id = args["findingId"]
    token = args["confirmToken"]

    # --- Look up finding ---
    finding = store.get_finding(finding_id)
    if not finding:
        return err("E_NOT_FOUND", "Finding not found.", {"findingId": finding_id})

    # --- 1. Verify token ---
    try:
        payload = verify_confirm_token(token, token_secret)
    except TimeoutError:
        return err("E_CONFIRM_TOKEN_EXPIRED", "Confirmation token expired.", {"findingId": finding_id})
    except ValueError:
        return err("E_CONFIRM_TOKEN_INVALID", "Confirmation token invalid.", {"findingId": finding_id})

    # Verify token bindings match finding
    identity = finding.evidence.get("identity", {})
    expected_bindings = {
        "findingId": finding.findingId,
        "rootId": finding.rootId,
        "scanId": finding.scanId,
        "volumeSerial": identity.get("volumeSerial"),
        "fileId": identity.get("fileId"),
        "strategy": STRATEGY_V1,
        "reparsePolicy": REPARSE_POLICY,
    }
    for key, expected_val in expected_bindings.items():
        if payload.get(key) != expected_val:
            return err(
                "E_CONFIRM_TOKEN_INVALID",
                f"Token binding mismatch on '{key}'.",
                {"findingId": finding_id},
            )

    # --- 2. Root confinement ---
    root = roots.get(finding.rootId)
    if not root:
        return err("E_ROOT_NOT_ALLOWED", "Root not allowlisted.", {"rootId": finding.rootId})

    target_abs = os.path.abspath(finding.observedPath)
    root_abs = os.path.abspath(root.path)
    if not is_under_root(target_abs, root_abs):
        return err(
            "E_TRAVERSAL_REJECTED",
            "Target escapes allowlisted root.",
            {"target": target_abs, "root": root_abs},
        )

    # --- 3. deny_all reparse policy ---
    if is_reparse_point(target_abs):
        return err(
            "E_REPARSE_POLICY_BLOCKED",
            "Reparse points are blocked by policy (deny_all).",
            {"target": target_abs},
        )

    # --- 4. Re-check identity (TOCTOU) ---
    try:
        vol_now, fid_now = get_identity(target_abs)
    except FileNotFoundError:
        return err("E_NOT_FOUND", "Target no longer exists.", {"target": target_abs})
    except OSError as e:
        return err(
            "E_INTERNAL",
            "Failed to open target for identity verification.",
            {"target": target_abs, "errno": e.args[0]},
        )

    if vol_now != identity.get("volumeSerial") or fid_now != identity.get("fileId"):
        return err(
            "E_CHANGED_SINCE_SCAN",
            "Target changed since scan (identity mismatch).",
            {
                "target": target_abs,
                "expected": identity,
                "observed": {"volumeSerial": vol_now, "fileId": fid_now},
            },
        )

    # --- 5. Empty-only directory rule ---
    if finding.entryType == "dir":
        try:
            with os.scandir(target_abs) as it:
                if any(True for _ in it):
                    return err(
                        "E_DIR_NOT_EMPTY",
                        "Directory is not empty; v1 only deletes empty directories.",
                        {"target": target_abs},
                    )
        except PermissionError:
            return err(
                "E_ACCESS_DENIED",
                "Access denied while checking directory contents.",
                {"target": target_abs},
            )

    # --- 6. Delete using extended namespace ---
    ext_path = to_extended_path(target_abs)
    start = time.time()
    try:
        if finding.entryType == "dir":
            os.rmdir(ext_path)
        else:
            os.remove(ext_path)
    except PermissionError:
        return err(
            "E_ACCESS_DENIED",
            "Access denied while deleting target.",
            {"target": target_abs, "strategy": STRATEGY_V1},
        )
    except OSError as e:
        win_err = getattr(e, "winerror", None)
        if win_err == 32:
            return err(
                "E_IN_USE",
                "Target is in use by another process.",
                {"target": target_abs, "strategy": STRATEGY_V1, "win32LastError": 32},
                next_steps=[{
                    "action": "WHO_IS_USING",
                    "tool": "who_is_using",
                    "args": {"findingId": finding_id},
                }],
            )
        if win_err in (23, 1117, 1392):
            return err(
                "E_IO_ERROR",
                "I/O error or corruption suspected.",
                {"target": target_abs, "win32LastError": win_err},
            )
        if win_err == 145:  # ERROR_DIR_NOT_EMPTY
            return err(
                "E_DIR_NOT_EMPTY",
                "Directory is not empty.",
                {"target": target_abs, "win32LastError": 145},
            )
        return err(
            "E_INTERNAL",
            "Delete failed.",
            {"target": target_abs, "win32LastError": win_err, "errno": e.errno},
        )

    dur_ms = int((time.time() - start) * 1000)
    return ok({
        "findingId": finding.findingId,
        "deleted": True,
        "strategy": STRATEGY_V1,
        "entryType": finding.entryType,
        "telemetry": {"durationMs": dur_ms, "usedExtendedNamespace": True},
        "warnings": [],
    })


def handle_who_is_using(
    args: dict[str, Any],
    store: Store,
) -> dict[str, Any]:
    """Tier A attribution: list processes using the target (Phase 1 stub)."""
    return who_is_using(args, store)


# --- Internal helpers ---


def _safe_get_identity(path: str) -> tuple[str | None, str | None]:
    """Get file identity, returning (None, None) on failure."""
    try:
        return get_identity(path)
    except Exception:
        return None, None


def _make_finding(
    root_id: str,
    scan_id: str,
    root_abs: str,
    full_path: str,
    entry: os.DirEntry[str],
    hazards: list[dict[str, Any]],
    vol: str | None,
    fid: str | None,
) -> Finding:
    """Build a Finding from scan data."""
    rel = os.path.relpath(full_path, root_abs)
    name = os.path.basename(full_path)
    base, ext = parse_basename(name)
    entry_type = "dir" if entry.is_dir(follow_symlinks=False) else "file"
    canonical = to_extended_path(full_path)

    evidence = {
        "fs": {
            "existsAtScan": True,
            "sizeBytes": _safe_size(entry, entry_type),
            "attributes": [],
            "isDirectory": entry_type == "dir",
            "isReparsePoint": any(h["code"] == "REPARSE_POINT_PRESENT" for h in hazards),
        },
        "win32": {
            "requiresExtendedPath": True,
            "hasTrailingDotOrSpace": has_trailing_dot_or_space(name),
            "exceedsMaxPathLegacy": len(canonical) > 260,
            "isUncPath": full_path.startswith("\\\\"),
            "isDevicePath": False,
            "isAdsSuspected": ":" in name[2:] if len(name) > 2 else False,
        },
        "identity": {
            "volumeSerial": vol,
            "fileId": fid,
            "fingerprintVersion": 1,
        },
    }

    return Finding(
        findingId=store_ref.new_id("fnd"),
        rootId=root_id,
        scanId=scan_id,
        relativePath=rel,
        observedPath=full_path,
        canonicalPath=canonical,
        entryType=entry_type,
        name=name,
        baseName=base,
        extension=ext,
        hazards=hazards,
        evidence=evidence,
    )


def _safe_size(entry: os.DirEntry[str], entry_type: str) -> int | None:
    """Get file size, returning None for directories or on failure."""
    if entry_type == "dir":
        return None
    try:
        return entry.stat(follow_symlinks=False).st_size
    except Exception:
        return None


# Module-level store reference — set by server.py at startup
store_ref: Store = Store()


def set_store(store: Store) -> None:
    """Set the module-level store reference. Called by server.py at init."""
    global store_ref
    store_ref = store
