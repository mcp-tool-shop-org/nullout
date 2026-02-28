"""Configuration: allowlisted roots, token secret, TTL."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Root:
    root_id: str
    display_name: str
    path: str  # win32 style, e.g. C:\Users\me\Downloads


REPARSE_POLICY = "deny_all"
TOKEN_TTL_SECONDS = 300  # 5 minutes
STRATEGY_V1 = "WIN_EXTENDED_PATH_DELETE"


def get_token_secret() -> bytes:
    """Return token signing secret from env. Fail closed if missing."""
    secret = os.environ.get("NULLOUT_TOKEN_SECRET", "")
    if not secret:
        raise RuntimeError(
            "NULLOUT_TOKEN_SECRET environment variable is required. "
            "Generate a random value: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret.encode("utf-8")


def load_roots() -> dict[str, Root]:
    """Load allowlisted roots from NULLOUT_ROOTS env var.

    Format: semicolon-separated absolute paths.
    Example: NULLOUT_ROOTS=C:\\Users\\me\\Downloads;C:\\temp\\cleanup

    Fail closed if no roots configured.
    """
    raw = os.environ.get("NULLOUT_ROOTS", "")
    if not raw:
        raise RuntimeError(
            "NULLOUT_ROOTS environment variable is required. "
            "Set semicolon-separated absolute paths: "
            "NULLOUT_ROOTS=C:\\Users\\me\\Downloads;C:\\temp"
        )

    roots: dict[str, Root] = {}
    for i, path in enumerate(raw.split(";")):
        path = path.strip()
        if not path:
            continue
        abs_path = os.path.abspath(path)
        if not os.path.isdir(abs_path):
            raise RuntimeError(f"Configured root does not exist or is not a directory: {abs_path}")
        root_id = f"root_{i}"
        display_name = os.path.basename(abs_path) or abs_path
        roots[root_id] = Root(root_id=root_id, display_name=display_name, path=abs_path)

    if not roots:
        raise RuntimeError("NULLOUT_ROOTS is set but contains no valid paths.")

    return roots
