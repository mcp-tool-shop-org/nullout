"""Restart Manager — process attribution via rstrtmgr.dll.

Queries Windows Restart Manager to identify processes holding handles to
a given filesystem entry. Used by the who_is_using tool for lock attribution.

Never kills or restarts processes — read-only attribution only.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
from typing import Any

from nullout.config import Root, REPARSE_POLICY
from nullout.errors import err, ok
from nullout.hazards import has_trailing_dot_or_space
from nullout.models import Finding
from nullout.store import Store
from nullout.win_identity import get_identity
from nullout.win_paths import is_under_root, is_reparse_point, safe_abspath

# --- RM constants ---

CCH_RM_SESSION_KEY = 33  # GUID string (32 chars) + NUL
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63

ERROR_MORE_DATA = 234
ERROR_SUCCESS = 0

_RM_APP_TYPE_NAMES: dict[int, str] = {
    0: "unknown",
    1: "main_window",
    2: "other_window",
    3: "service",
    4: "explorer",
    5: "console",
    6: "critical",
}


# --- RM structures ---

class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.DWORD),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


# --- RM DLL bindings (fail gracefully if unavailable) ---

_RM_AVAILABLE = False

try:
    _rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)

    _RmStartSession = _rstrtmgr.RmStartSession
    _RmStartSession.argtypes = [
        ctypes.POINTER(wintypes.DWORD),  # pSessionHandle
        wintypes.DWORD,                  # dwSessionFlags (reserved, 0)
        wintypes.LPWSTR,                 # strSessionKey
    ]
    _RmStartSession.restype = wintypes.DWORD

    _RmRegisterResources = _rstrtmgr.RmRegisterResources
    _RmRegisterResources.argtypes = [
        wintypes.DWORD,                           # dwSessionHandle
        wintypes.UINT,                             # nFiles
        ctypes.POINTER(wintypes.LPCWSTR),          # rgsFileNames
        wintypes.UINT,                             # nApplications (0)
        ctypes.POINTER(RM_UNIQUE_PROCESS),         # rgApplications (NULL)
        wintypes.UINT,                             # nServices (0)
        ctypes.POINTER(wintypes.LPCWSTR),          # rgsServiceNames (NULL)
    ]
    _RmRegisterResources.restype = wintypes.DWORD

    _RmGetList = _rstrtmgr.RmGetList
    _RmGetList.argtypes = [
        wintypes.DWORD,                        # dwSessionHandle
        ctypes.POINTER(wintypes.UINT),         # pnProcInfoNeeded
        ctypes.POINTER(wintypes.UINT),         # pnProcInfo
        ctypes.POINTER(RM_PROCESS_INFO),       # rgAffectedApps (can be NULL)
        ctypes.POINTER(wintypes.DWORD),        # lpdwRebootReasons
    ]
    _RmGetList.restype = wintypes.DWORD

    _RmEndSession = _rstrtmgr.RmEndSession
    _RmEndSession.argtypes = [wintypes.DWORD]
    _RmEndSession.restype = wintypes.DWORD

    _RM_AVAILABLE = True
except (OSError, AttributeError):
    pass


def rm_available() -> bool:
    """Check if Restart Manager DLL is loaded and usable."""
    return _RM_AVAILABLE


def query_file_lockers(path: str) -> list[dict[str, Any]]:
    """Query Restart Manager for processes using the given file path.

    Args:
        path: Standard Win32 absolute path. RM works best with normal
              paths (not \\\\?\\\\ extended). For entries with trailing
              dots/spaces, Win32 normalization may prevent RM from
              finding all lockers.

    Returns:
        List of process info dicts with keys: pid, appName,
        serviceShortName, type, sessionId, restartable.

    Raises:
        RuntimeError: If RM DLL is not available.
        OSError: If RM session or query fails.
    """
    if not _RM_AVAILABLE:
        raise RuntimeError("Restart Manager (rstrtmgr.dll) is not available.")

    session_handle = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY)

    rc = _RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if rc != ERROR_SUCCESS:
        raise OSError(rc, f"RmStartSession failed with error {rc}")

    try:
        # Register the file resource
        files_array = (wintypes.LPCWSTR * 1)(path)
        rc = _RmRegisterResources(
            session_handle.value,
            1, files_array,
            0, None,
            0, None,
        )
        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"RmRegisterResources failed with error {rc}")

        # First call: determine buffer size
        n_needed = wintypes.UINT(0)
        n_info = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD(0)

        rc = _RmGetList(
            session_handle.value,
            ctypes.byref(n_needed),
            ctypes.byref(n_info),
            None,
            ctypes.byref(reboot_reasons),
        )

        if rc == ERROR_SUCCESS and n_needed.value == 0:
            return []

        if rc not in (ERROR_SUCCESS, ERROR_MORE_DATA):
            raise OSError(rc, f"RmGetList (sizing) failed with error {rc}")

        # Allocate buffer and retry
        buf_size = max(n_needed.value, 1)
        proc_info_array = (RM_PROCESS_INFO * buf_size)()
        n_info = wintypes.UINT(buf_size)

        rc = _RmGetList(
            session_handle.value,
            ctypes.byref(n_needed),
            ctypes.byref(n_info),
            proc_info_array,
            ctypes.byref(reboot_reasons),
        )

        if rc != ERROR_SUCCESS:
            raise OSError(rc, f"RmGetList failed with error {rc}")

        results: list[dict[str, Any]] = []
        for i in range(n_info.value):
            info = proc_info_array[i]
            app_type_code = info.ApplicationType
            results.append({
                "pid": info.Process.dwProcessId,
                "appName": info.strAppName or "",
                "serviceShortName": info.strServiceShortName or "",
                "type": _RM_APP_TYPE_NAMES.get(app_type_code, f"unknown_{app_type_code}"),
                "sessionId": info.TSSessionId,
                "restartable": bool(info.bRestartable),
            })

        return results
    finally:
        _RmEndSession(session_handle.value)


def who_is_using(
    args: dict[str, Any],
    roots: dict[str, Root],
    store: Store,
) -> dict[str, Any]:
    """Identify processes currently using a finding's target.

    Safety checks mirror delete_entry:
    1. Finding exists
    2. Root confinement
    3. deny_all reparse policy
    4. Identity verification (target still exists and hasn't changed)
    5. Query RM with observedPath (normal Win32 path)
    """
    finding_id = args["findingId"]
    finding = store.get_finding(finding_id)
    if not finding:
        return err("E_NOT_FOUND", "Finding not found.", {"findingId": finding_id})

    # --- Root confinement ---
    root = roots.get(finding.rootId)
    if not root:
        return err("E_ROOT_NOT_ALLOWED", "Root not allowlisted.", {"rootId": finding.rootId})

    target_abs = safe_abspath(finding.observedPath)
    root_abs = os.path.abspath(root.path)  # Root paths never have trailing dots/spaces
    if not is_under_root(target_abs, root_abs):
        return err(
            "E_TRAVERSAL_REJECTED",
            "Target escapes allowlisted root.",
            {"target": target_abs, "root": root_abs},
        )

    # --- deny_all reparse policy ---
    if is_reparse_point(target_abs):
        return err(
            "E_REPARSE_POLICY_BLOCKED",
            "Reparse points are blocked by policy (deny_all).",
            {"target": target_abs},
        )

    # --- Identity verification ---
    identity = finding.evidence.get("identity", {})
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

    # --- RM availability ---
    if not rm_available():
        return ok({
            "findingId": finding_id,
            "processes": [],
            "confidence": "low",
            "limitations": ["Restart Manager (rstrtmgr.dll) is not available on this system."],
        })

    # --- Query RM ---
    limitations: list[str] = []
    if has_trailing_dot_or_space(finding.name):
        limitations.append(
            "Target has trailing dot/space; Win32 path normalization may prevent "
            "Restart Manager from identifying all lockers."
        )

    try:
        processes = query_file_lockers(target_abs)
    except OSError as e:
        return err(
            "E_INTERNAL",
            "Restart Manager query failed.",
            {"target": target_abs, "rmError": e.args[0]},
        )

    # Normalized-path fallback hint: if RM returned nothing and the entry
    # has trailing dot/space, try querying with the normalized name.
    # Win32 strips trailing chars, so RM may find lockers for the
    # normalized path even though it missed the exact on-disk entry.
    if not processes and limitations and has_trailing_dot_or_space(finding.name):
        normalized = target_abs.rstrip(". ")
        if normalized != target_abs:
            try:
                hint_procs = query_file_lockers(normalized)
                for p in hint_procs:
                    p["source"] = "normalized_path_hint"
                processes = hint_procs
                if hint_procs:
                    limitations.append(
                        "Results are from a normalized-path hint query (trailing "
                        "chars stripped). These processes may not hold the exact "
                        "on-disk entry."
                    )
            except OSError:
                pass  # Non-fatal: hint is best-effort

    # Confidence: high if no limitations, medium if limitations but results found,
    # low if no results and limitations exist
    if processes:
        confidence = "medium" if limitations else "high"
    else:
        confidence = "low" if limitations else "medium"

    return ok({
        "findingId": finding_id,
        "processes": processes,
        "confidence": confidence,
        "limitations": limitations,
    })
