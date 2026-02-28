"""Data models: Finding, PlanEntry, result shapes."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    findingId: str
    rootId: str
    scanId: str
    relativePath: str
    observedPath: str
    canonicalPath: str
    entryType: str  # "file" | "dir"
    name: str
    baseName: str
    extension: str
    hazards: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
