"""Windows path utilities: extended path conversion, root confinement, reparse detection."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os


def to_extended_path(path: str) -> str:
    """Convert an absolute path to \\\\?\\ extended form.

    Local:  C:\\foo  -> \\\\?\\C:\\foo
    UNC:    \\\\server\\share\\foo -> \\\\?\\UNC\\server\\share\\foo
    Already extended: returned as-is.
    """
    path = os.path.abspath(path)
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        # UNC path
        return "\\\\?\\UNC\\" + path.lstrip("\\")
    return "\\\\?\\" + path


def is_under_root(target_abs: str, root_abs: str) -> bool:
    """Check if target is inside root using case-insensitive normalized comparison."""
    t = os.path.normcase(os.path.normpath(target_abs))
    r = os.path.normcase(os.path.normpath(root_abs))
    if not r.endswith(os.sep):
        r += os.sep
    return t.startswith(r) or t == r.rstrip(os.sep)


def is_reparse_point(path: str) -> bool:
    """Check if path is a reparse point (symlink/junction/mount) via Win32 attributes."""
    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(wintypes.LPCWSTR(path))
        if attrs == 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False
