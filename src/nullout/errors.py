"""Error taxonomy helpers — structured error/success envelopes."""

from __future__ import annotations

from typing import Any


def err(
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    next_steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a structured error envelope."""
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "nextSteps": next_steps or [],
        },
    }


def ok(result: dict[str, Any]) -> dict[str, Any]:
    """Build a structured success envelope."""
    return {"ok": True, "result": result}
