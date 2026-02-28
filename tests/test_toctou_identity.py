"""Tests for TOCTOU identity mismatch detection."""

from __future__ import annotations

import os

import pytest

from nullout.models import Finding
from nullout.tools import handle_plan_cleanup, handle_delete_entry
from nullout.win_identity import get_identity


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_identity_mismatch_on_replace(temp_root, store, token_secret):
    """Replacing a file between scan and delete triggers E_CHANGED_SINCE_SCAN."""
    td, roots = temp_root

    # Create a file with a trailing dot (hazardous name)
    # Use extended path so trailing dot is preserved
    file_name = "testfile."
    file_path = os.path.join(td, file_name)
    ext_path = f"\\\\?\\{os.path.abspath(file_path)}"

    with open(ext_path, "w") as f:
        f.write("original")

    vol, fid = get_identity(file_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath=file_name,
        observedPath=file_path,
        canonicalPath=ext_path,
        entryType="file",
        name=file_name,
        baseName="testfile",
        extension=".",
        hazards=[{"code": "WIN_TRAILING_DOT_SPACE", "severity": "medium", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    # Plan cleanup
    plan = handle_plan_cleanup(
        {"findingIds": [finding.findingId], "requestedActions": ["DELETE"]},
        store, token_secret,
    )
    assert plan["ok"]
    ctok = plan["result"]["entries"][0]["confirmToken"]

    # TOCTOU: delete and recreate (new file ID)
    os.remove(ext_path)
    with open(ext_path, "w") as f:
        f.write("replacement with different identity")

    # Attempt delete — should detect identity mismatch
    result = handle_delete_entry(
        {"findingId": finding.findingId, "confirmToken": ctok},
        roots, store, token_secret,
    )
    assert not result["ok"]
    assert result["error"]["code"] == "E_CHANGED_SINCE_SCAN"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_identity_match_on_unchanged(temp_root, store, token_secret):
    """File not changed between scan and delete should succeed."""
    td, roots = temp_root

    file_name = "testfile."
    file_path = os.path.join(td, file_name)
    ext_path = f"\\\\?\\{os.path.abspath(file_path)}"

    with open(ext_path, "w") as f:
        f.write("original")

    vol, fid = get_identity(file_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath=file_name,
        observedPath=file_path,
        canonicalPath=ext_path,
        entryType="file",
        name=file_name,
        baseName="testfile",
        extension=".",
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

    # No TOCTOU: delete without replacing
    result = handle_delete_entry(
        {"findingId": finding.findingId, "confirmToken": ctok},
        roots, store, token_secret,
    )
    assert result["ok"]
    assert result["result"]["deleted"] is True
