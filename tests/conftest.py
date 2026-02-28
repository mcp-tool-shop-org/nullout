"""Shared test fixtures for NullOut tests."""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest

from nullout.config import Root
from nullout.store import Store
from nullout.tools import set_store


@pytest.fixture
def temp_root() -> Generator[tuple[str, dict[str, Root]], None, None]:
    """Create a temporary directory and register it as an allowlisted root."""
    with tempfile.TemporaryDirectory() as td:
        root_id = "root_test"
        roots = {root_id: Root(root_id=root_id, display_name="Test", path=td)}
        yield td, roots


@pytest.fixture
def store() -> Store:
    """Create a fresh in-memory store and set it as the module-level ref."""
    s = Store()
    set_store(s)
    return s


@pytest.fixture
def token_secret() -> bytes:
    return b"test-secret-do-not-use-in-production"
