"""Shared test fixtures for NullOut tests."""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest

from nullout.config import Root
from nullout.store import Store
from nullout.tools import set_store
from nullout.win_paths import to_extended_path


def _cleanup_extended(path: str) -> None:
    """Remove directory tree including entries with trailing dots/spaces.

    Standard shutil.rmtree uses Win32 paths which can't see or delete
    entries created with \\?\\ prefix that have trailing dots/spaces.
    """
    ext = to_extended_path(path)
    try:
        for entry in os.scandir(ext):
            full_ext = to_extended_path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                _cleanup_extended(entry.path)
                try:
                    os.rmdir(full_ext)
                except OSError:
                    pass
            else:
                try:
                    os.remove(full_ext)
                except OSError:
                    pass
    except PermissionError:
        pass


@pytest.fixture
def temp_root() -> Generator[tuple[str, dict[str, Root]], None, None]:
    """Create a temporary directory and register it as an allowlisted root."""
    td = tempfile.mkdtemp()
    try:
        root_id = "root_test"
        roots = {root_id: Root(root_id=root_id, display_name="Test", path=td)}
        yield td, roots
    finally:
        # Clean up hazardous entries via extended paths, then remove the root
        _cleanup_extended(td)
        try:
            os.rmdir(td)
        except OSError:
            pass


@pytest.fixture
def store() -> Store:
    """Create a fresh in-memory store and set it as the module-level ref."""
    s = Store()
    set_store(s)
    return s


@pytest.fixture
def token_secret() -> bytes:
    return b"test-secret-do-not-use-in-production"
