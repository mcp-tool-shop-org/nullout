"""Tests for Restart Manager process attribution.

Deterministic tests that verify RM ctypes bindings and the who_is_using
tool handler, including safety checks (confinement, identity, reparse).
"""

from __future__ import annotations

import os
import tempfile

import pytest

from nullout.restart_manager import rm_available, query_file_lockers


# --- Pure RM query tests ---


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_rm_finds_current_process():
    """RM should find this test process when we hold a file handle open."""
    if not rm_available():
        pytest.skip("Restart Manager not available")

    path = tempfile.mktemp(suffix=".txt")
    # Create and close to establish the file
    with open(path, "w") as f:
        f.write("lock test")

    try:
        # Re-open with a held handle — RM should detect this
        handle = open(path, "r+b")
        try:
            processes = query_file_lockers(path)
            pids = [p["pid"] for p in processes]
            assert os.getpid() in pids, (
                f"Expected PID {os.getpid()} in {pids}; "
                f"RM returned {len(processes)} process(es)"
            )

            # Verify process info structure
            our_proc = next(p for p in processes if p["pid"] == os.getpid())
            assert "appName" in our_proc
            assert "type" in our_proc
            assert isinstance(our_proc["type"], str) and our_proc["type"]
            assert isinstance(our_proc["sessionId"], int)
            assert isinstance(our_proc["restartable"], bool)
        finally:
            handle.close()
    finally:
        os.unlink(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_rm_empty_when_unlocked():
    """RM returns empty list for an unlocked file."""
    if not rm_available():
        pytest.skip("Restart Manager not available")

    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write("no locks")

    try:
        # File handle is closed — no locks
        processes = query_file_lockers(path)
        assert processes == [], f"Expected no lockers, got {processes}"
    finally:
        os.unlink(path)


# --- Integration tests through the who_is_using tool handler ---


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_who_is_using_finds_locker(temp_root, store):
    """who_is_using returns process info for a locked file inside root."""
    if not rm_available():
        pytest.skip("Restart Manager not available")

    from nullout.models import Finding
    from nullout.tools import handle_who_is_using
    from nullout.win_identity import get_identity
    from nullout.win_paths import to_extended_path

    td, roots = temp_root

    # Create a normal file inside the root
    file_path = os.path.join(td, "locked_file.txt")
    with open(file_path, "w") as f:
        f.write("content")

    vol, fid = get_identity(file_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="locked_file.txt",
        observedPath=file_path,
        canonicalPath=to_extended_path(file_path),
        entryType="file",
        name="locked_file.txt",
        baseName="locked_file",
        extension=".txt",
        hazards=[{"code": "WIN_RESERVED_DEVICE_BASENAME", "severity": "high", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    # Hold a handle open so RM can find us
    handle = open(file_path, "r+b")
    try:
        result = handle_who_is_using(
            {"findingId": finding.findingId},
            roots, store,
        )
        assert result["ok"], f"Expected ok but got error: {result}"
        pids = [p["pid"] for p in result["result"]["processes"]]
        assert os.getpid() in pids, (
            f"Expected PID {os.getpid()} in {pids}"
        )
        assert result["result"]["confidence"] in ("high", "medium")
    finally:
        handle.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_who_is_using_empty_when_unlocked(temp_root, store):
    """who_is_using returns empty process list for an unlocked file."""
    if not rm_available():
        pytest.skip("Restart Manager not available")

    from nullout.models import Finding
    from nullout.tools import handle_who_is_using
    from nullout.win_identity import get_identity
    from nullout.win_paths import to_extended_path

    td, roots = temp_root

    file_path = os.path.join(td, "unlocked_file.txt")
    with open(file_path, "w") as f:
        f.write("content")

    vol, fid = get_identity(file_path)

    finding = Finding(
        findingId=store.new_id("fnd"),
        rootId="root_test",
        scanId="scan_test",
        relativePath="unlocked_file.txt",
        observedPath=file_path,
        canonicalPath=to_extended_path(file_path),
        entryType="file",
        name="unlocked_file.txt",
        baseName="unlocked_file",
        extension=".txt",
        hazards=[{"code": "WIN_RESERVED_DEVICE_BASENAME", "severity": "high", "confidence": "high"}],
        evidence={
            "identity": {"volumeSerial": vol, "fileId": fid, "fingerprintVersion": 1},
            "fs": {"existsAtScan": True},
            "win32": {"requiresExtendedPath": True},
        },
    )
    store.put_finding(finding)

    # File is closed — no locks
    result = handle_who_is_using(
        {"findingId": finding.findingId},
        roots, store,
    )
    assert result["ok"], f"Expected ok but got error: {result}"
    assert result["result"]["processes"] == []
    assert result["result"]["confidence"] == "medium"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_who_is_using_rejects_outside_root(temp_root, store):
    """who_is_using must reject findings that escape the root."""
    from nullout.models import Finding
    from nullout.tools import handle_who_is_using

    td, roots = temp_root

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

    result = handle_who_is_using(
        {"findingId": finding.findingId},
        roots, store,
    )
    assert not result["ok"]
    assert result["error"]["code"] == "E_TRAVERSAL_REJECTED"


@pytest.mark.skipif(os.name != "nt", reason="Windows-only")
def test_who_is_using_rejects_missing_finding(store):
    """who_is_using returns E_NOT_FOUND for unknown findingId."""
    from nullout.tools import handle_who_is_using

    result = handle_who_is_using(
        {"findingId": "fnd_nonexistent"},
        {}, store,
    )
    assert not result["ok"]
    assert result["error"]["code"] == "E_NOT_FOUND"
