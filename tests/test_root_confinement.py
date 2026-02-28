"""Tests for root confinement: traversal rejection, case insensitivity."""

from __future__ import annotations

import os

import pytest

from nullout.win_paths import is_under_root


def test_child_is_under_root(tmp_path):
    root = str(tmp_path)
    child = os.path.join(root, "subdir", "file.txt")
    assert is_under_root(child, root)


def test_root_is_under_itself(tmp_path):
    root = str(tmp_path)
    assert is_under_root(root, root)


def test_sibling_is_not_under_root(tmp_path):
    root = str(tmp_path)
    sibling = os.path.join(os.path.dirname(root), "other_dir", "file.txt")
    assert not is_under_root(sibling, root)


def test_traversal_escape(tmp_path):
    root = str(tmp_path)
    escape = os.path.join(root, "..", "..", "etc", "passwd")
    assert not is_under_root(escape, root)


def test_case_insensitive(tmp_path):
    root = str(tmp_path)
    # Windows paths are case-insensitive
    upper_child = os.path.join(root.upper(), "FILE.TXT")
    assert is_under_root(upper_child, root)


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_delete_rejects_finding_outside_root(temp_root, store, token_secret):
    """Integration: delete_entry must reject a finding whose path escapes root."""
    from nullout.models import Finding
    from nullout.tools import handle_plan_cleanup, handle_delete_entry

    td, roots = temp_root

    # Craft a finding that points outside the root
    outside_path = os.path.abspath(os.path.join(td, "..", "escape.txt"))
    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="..\\escape.txt",
        observedPath=outside_path,
        canonicalPath=f"\\\\?\\{outside_path}",
        entryType="file",
        name="escape.txt",
        baseName="escape",
        extension=".txt",
        hazards=[{"code": "WIN_RESERVED_DEVICE_BASENAME", "severity": "high", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": "0x00000000", "fileId": "0x0000000000000000", "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    # Plan + get token
    plan = handle_plan_cleanup(
        {"findingIds": [finding.findingId], "requestedActions": ["DELETE"]},
        store, token_secret,
    )
    assert plan["ok"]
    ctok = plan["result"]["entries"][0]["confirmToken"]

    # Attempt delete
    result = handle_delete_entry(
        {"findingId": finding.findingId, "confirmToken": ctok},
        roots, store, token_secret,
    )
    assert not result["ok"], f"Expected failure but got ok: {result}"
    assert result["error"]["code"] == "E_TRAVERSAL_REJECTED", f"Got error: {result['error']}"
