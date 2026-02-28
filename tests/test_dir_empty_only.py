"""Tests for empty-only directory deletion rule."""

from __future__ import annotations

import os

import pytest

from nullout.models import Finding
from nullout.tools import handle_plan_cleanup, handle_delete_entry
from nullout.win_identity import get_identity
from nullout.win_paths import to_extended_path


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_non_empty_dir_refused(temp_root, store, token_secret):
    """Deleting a non-empty directory must return E_DIR_NOT_EMPTY."""
    td, roots = temp_root

    # Create a directory with a child file using extended paths
    # (trailing space requires \\?\ to preserve on NTFS)
    dir_path = os.path.join(td, "notempty ")
    ext_dir = to_extended_path(dir_path)
    os.makedirs(ext_dir, exist_ok=True)
    child = ext_dir + "\\child.txt"
    with open(child, "w") as f:
        f.write("content")

    vol, fid = get_identity(dir_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="notempty ",
        observedPath=dir_path,
        canonicalPath=f"\\\\?\\{dir_path}",
        entryType="dir",
        name="notempty ",
        baseName="notempty ",
        extension="",
        hazards=[{"code": "WIN_TRAILING_DOT_SPACE", "severity": "medium", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    plan = handle_plan_cleanup(
        {"findingIds": [finding.findingId], "requestedActions": ["DELETE"]},
        store, token_secret,
    )
    assert plan["ok"]
    ctok = plan["result"]["entries"][0]["confirmToken"]

    result = handle_delete_entry(
        {"findingId": finding.findingId, "confirmToken": ctok},
        roots, store, token_secret,
    )
    assert not result["ok"]
    assert result["error"]["code"] == "E_DIR_NOT_EMPTY"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_empty_dir_succeeds(temp_root, store, token_secret):
    """Deleting an empty directory should succeed."""
    td, roots = temp_root

    # Create an empty directory with a trailing space (hazardous)
    dir_path = os.path.join(td, "empty ")
    # Use to_extended_path to preserve trailing space on NTFS
    ext_path = to_extended_path(dir_path)
    os.makedirs(ext_path, exist_ok=True)

    vol, fid = get_identity(dir_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="empty ",
        observedPath=dir_path,
        canonicalPath=f"\\\\?\\{dir_path}",
        entryType="dir",
        name="empty ",
        baseName="empty ",
        extension="",
        hazards=[{"code": "WIN_TRAILING_DOT_SPACE", "severity": "medium", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    plan = handle_plan_cleanup(
        {"findingIds": [finding.findingId], "requestedActions": ["DELETE"]},
        store, token_secret,
    )
    assert plan["ok"]
    ctok = plan["result"]["entries"][0]["confirmToken"]

    result = handle_delete_entry(
        {"findingId": finding.findingId, "confirmToken": ctok},
        roots, store, token_secret,
    )
    assert result["ok"], f"Expected ok but got: {result}"
    assert result["result"]["deleted"] is True
    assert not os.path.exists(ext_path)
