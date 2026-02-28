"""Tests for HMAC confirm tokens: creation, verification, expiry, tampering."""

from __future__ import annotations

import time

import pytest

from nullout.tokens import make_confirm_token, verify_confirm_token


SECRET = b"test-secret"


def _sample_payload(exp_offset: float = 300.0) -> dict:
    return {
        "findingId": "fnd_test_1",
        "rootId": "root_test",
        "scanId": "scan_test",
        "volumeSerial": "0x12345678",
        "fileId": "0x0000000000001234",
        "strategy": "WIN_EXTENDED_PATH_DELETE",
        "reparsePolicy": "deny_all",
        "exp": time.time() + exp_offset,
    }


def test_roundtrip():
    """Token can be created and verified."""
    payload = _sample_payload()
    token = make_confirm_token(payload, SECRET)
    decoded = verify_confirm_token(token, SECRET)
    assert decoded["findingId"] == "fnd_test_1"
    assert decoded["volumeSerial"] == "0x12345678"


def test_expired_token():
    """Expired token raises TimeoutError."""
    payload = _sample_payload(exp_offset=-10.0)  # already expired
    token = make_confirm_token(payload, SECRET)
    with pytest.raises(TimeoutError):
        verify_confirm_token(token, SECRET)


def test_wrong_secret():
    """Token signed with different secret fails verification."""
    payload = _sample_payload()
    token = make_confirm_token(payload, SECRET)
    with pytest.raises(ValueError):
        verify_confirm_token(token, b"wrong-secret")


def test_tampered_token():
    """Modified token fails signature check."""
    payload = _sample_payload()
    token = make_confirm_token(payload, SECRET)
    # Flip a character in the middle of the token
    chars = list(token)
    mid = len(chars) // 2
    chars[mid] = "A" if chars[mid] != "A" else "B"
    tampered = "".join(chars)
    with pytest.raises((ValueError, Exception)):
        verify_confirm_token(tampered, SECRET)
