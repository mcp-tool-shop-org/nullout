"""Windows path utilities: extended path conversion, root confinement, reparse detection."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os


def safe_abspath(path: str) -> str:
    """Make path absolute, preserving trailing dots/spaces.

    Unlike os.path.abspath, this does NOT call GetFullPathNameW which
    strips trailing dots and spaces from path components.
    """
    if os.path.isabs(path):
        return path.replace("/", "\\")
    return os.path.join(os.getcwd(), path).replace("/", "\\")


def to_extended_path(path: str) -> str:
    """Convert an absolute path to \\\\?\\ extended form.

    Local:  C:\\foo  -> \\\\?\\C:\\foo
    UNC:    \\\\server\\share\\foo -> \\\\?\\UNC\\server\\share\\foo
    Already extended: returned as-is.

    Does NOT use os.path.abspath() because GetFullPathNameW normalizes
    away trailing dots and spaces — the exact characters NullOut exists to handle.
    """
    if path.startswith("\\\\?\\"):
        return path
    # Make absolute without Win32 normalization
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    path = path.replace("/", "\\")
    if path.startswith("\\\\"):
        # UNC path: \\server\share -> \\?\UNC\server\share
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def is_under_root(target_abs: str, root_abs: str) -> bool:
    """Check if target is inside root using case-insensitive normalized comparison."""
    t = os.path.normcase(os.path.normpath(target_abs))
    r = os.path.normcase(os.path.normpath(root_abs))
    if not r.endswith(os.sep):
        r += os.sep
    return t.startswith(r) or t == r.rstrip(os.sep)


# --- Properly typed Win32 binding for GetFileAttributesW ---
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_GetFileAttributesW = _kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_GetFileAttributesW.restype = wintypes.DWORD  # MUST be unsigned — signed returns -1 instead of 0xFFFFFFFF

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def is_reparse_point(path: str) -> bool:
    """Check if path is a reparse point (symlink/junction/mount) via Win32 attributes.

    Uses extended-path prefix to correctly query entries with trailing dots/spaces
    that Win32 would otherwise normalize away.
    """
    ext_path = to_extended_path(path)
    try:
        attrs = _GetFileAttributesW(ext_path)
        if attrs == _INVALID_FILE_ATTRIBUTES:
            return False
        return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False
