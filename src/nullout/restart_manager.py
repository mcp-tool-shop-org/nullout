"""Restart Manager (Tier A) — Phase 1 stub.

Full implementation will use rstrtmgr.dll ctypes bindings:
RmStartSession, RmRegisterResources, RmGetList, RmEndSession.
"""

from __future__ import annotations

from typing import Any

from nullout.errors import err, ok
from nullout.store import Store


def who_is_using(args: dict[str, Any], store: Store) -> dict[str, Any]:
    """Identify processes currently using a finding's target.

    Phase 1: returns a stub response indicating RM is not yet wired.
    """
    finding_id = args["findingId"]
    finding = store.get_finding(finding_id)
    if not finding:
        return err("E_NOT_FOUND", "Finding not found.", {"findingId": finding_id})

    return ok({
        "findingId": finding_id,
        "processes": [],
        "confidence": "low",
        "limitations": [
            "Restart Manager integration is not yet wired. "
            "Implement via rstrtmgr.dll ctypes bindings."
        ],
    })
