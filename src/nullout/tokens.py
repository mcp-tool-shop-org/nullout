"""HMAC-SHA256 confirm tokens with bindings + TTL."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def make_confirm_token(payload: dict[str, Any], secret: bytes) -> str:
    """Create an HMAC-signed confirm token.

    Payload must include 'exp' (expiry timestamp).
    Token format: base64(json_body) + "." + base64(hmac_signature)
    The "." separator is in the outer ASCII layer, not inside base64,
    so it can never collide with encoded content.
    """
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret, body, hashlib.sha256).digest()
    body_b64 = base64.urlsafe_b64encode(body).decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii")
    return f"{body_b64}.{sig_b64}"


def verify_confirm_token(token: str, secret: bytes) -> dict[str, Any]:
    """Verify and decode a confirm token.

    Raises ValueError if signature is invalid.
    Raises TimeoutError if token is expired.
    """
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Token has no signature separator")

    body_b64, sig_b64 = parts

    try:
        body = base64.urlsafe_b64decode(body_b64.encode("ascii"))
    except Exception as exc:
        raise ValueError("Token body is not valid base64") from exc

    try:
        sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
    except Exception as exc:
        raise ValueError("Token signature is not valid base64") from exc

    expected = hmac.new(secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Token signature is invalid")

    payload: dict[str, Any] = json.loads(body.decode("utf-8"))

    if time.time() > payload.get("exp", 0):
        raise TimeoutError("Token has expired")

    return payload
