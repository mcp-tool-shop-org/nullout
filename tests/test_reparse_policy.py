"""Tests for deny_all reparse point policy."""

from __future__ import annotations

import os
import subprocess

import pytest

from nullout.win_paths import is_reparse_point


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_junction_detected(tmp_path):
    """A junction should be detected as a reparse point."""
    target = tmp_path / "target_dir"
    target.mkdir()
    junction = tmp_path / "junction_link"

    # Create a junction (doesn't require admin)
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"mklink /J failed: {result.stderr}")

    assert is_reparse_point(str(junction))
    assert not is_reparse_point(str(target))


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_symlink_detected(tmp_path):
    """A symlink should be detected as a reparse point."""
    target = tmp_path / "target_file.txt"
    target.write_text("hello")
    link = tmp_path / "sym_link.txt"

    try:
        os.symlink(str(target), str(link))
    except OSError:
        pytest.skip("Symlink creation requires admin or Developer Mode")

    assert is_reparse_point(str(link))
    assert not is_reparse_point(str(target))


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_delete_refuses_reparse_point(temp_root, store, token_secret):
    """delete_entry must refuse a reparse point target under deny_all."""
    from nullout.models import Finding
    from nullout.tools import handle_plan_cleanup, handle_delete_entry
    from nullout.win_identity import get_identity

    td, roots = temp_root

    # Create a junction inside the root
    target_dir = os.path.join(td, "real_target")
    os.makedirs(target_dir)
    junction = os.path.join(td, "junction_link")
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", junction, target_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.skip("mklink /J failed")

    # Get identity (best-effort)
    try:
        vol, fid = get_identity(junction)
    except Exception:
        vol, fid = "0x00000000", "0x0000000000000000"

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="junction_link",
        observedPath=junction,
        canonicalPath=f"\\\\?\\{junction}",
        entryType="dir",
        name="junction_link",
        baseName="junction_link",
        extension="",
        hazards=[{"code": "REPARSE_POINT_PRESENT", "severity": "high", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True, "isReparsePoint": True},
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
    assert not result["ok"], f"Expected failure but got ok: {result}"
    assert result["error"]["code"] == "E_REPARSE_POLICY_BLOCKED", f"Got error: {result['error']}"
