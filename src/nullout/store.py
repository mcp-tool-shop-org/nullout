"""In-memory store for findings and scan indices. Pluggable later."""

from __future__ import annotations

import os
import time

from nullout.models import Finding


class Store:
    """In-memory finding store."""

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}
        self._scan_index: dict[str, list[str]] = {}  # scanId -> findingIds
        self._counter = 0

    def new_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}_{int(time.time() * 1000)}_{os.getpid()}_{self._counter}"

    def put_finding(self, finding: Finding) -> None:
        self._findings[finding.findingId] = finding

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def register_scan(self, scan_id: str, finding_ids: list[str]) -> None:
        self._scan_index[scan_id] = finding_ids

    def get_scan_findings(self, scan_id: str) -> list[str]:
        return self._scan_index.get(scan_id, [])
