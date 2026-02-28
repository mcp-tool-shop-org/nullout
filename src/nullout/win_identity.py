"""File identity capture via Win32: volume serial + file index.

Uses CreateFileW + GetFileInformationByHandle through ctypes.
No pywin32 dependency.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes

from nullout.win_paths import to_extended_path

# --- Win32 constants ---
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # required to open directories
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

# --- Win32 bindings ---
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_CreateFileW = _kernel32.CreateFileW
_CreateFileW.argtypes = [
    wintypes.LPCWSTR,  # lpFileName
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.DWORD,    # dwShareMode
    wintypes.LPVOID,   # lpSecurityAttributes
    wintypes.DWORD,    # dwCreationDisposition
    wintypes.DWORD,    # dwFlagsAndAttributes
    wintypes.HANDLE,   # hTemplateFile
]
_CreateFileW.restype = wintypes.HANDLE

_GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
_GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
_GetFileInformationByHandle.restype = wintypes.BOOL

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def get_identity(path: str) -> tuple[str, str]:
    """Return (volumeSerialHex, fileIdHex) for a filesystem entry.

    Uses the extended path namespace to handle reserved names.
    Opens with FILE_FLAG_BACKUP_SEMANTICS so directories work too.

    Raises OSError if the file cannot be opened.
    """
    ext_path = to_extended_path(path)
    share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

    handle = _CreateFileW(
        ext_path, GENERIC_READ, share,
        None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        raise OSError(error_code, f"CreateFileW failed: {path}")

    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not _GetFileInformationByHandle(handle, ctypes.byref(info)):
            error_code = ctypes.get_last_error()
            raise OSError(error_code, "GetFileInformationByHandle failed")

        vol = f"0x{info.dwVolumeSerialNumber:08X}"
        file_id = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        fid = f"0x{file_id:016X}"
        return vol, fid
    finally:
        _CloseHandle(handle)
