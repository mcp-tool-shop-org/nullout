"""Hazard detection: reserved device names, trailing dot/space, long paths, reparse."""

from __future__ import annotations

from typing import Any

# Win32 reserved device names (case-insensitive, even with extensions)
RESERVED_NAMES: set[str] = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def parse_basename(name: str) -> tuple[str, str]:
    """Split filename into (base, extension).

    For reserved-name detection, base is everything before the first dot.
    "NUL.tar.gz" -> ("NUL", ".tar.gz")
    "README"     -> ("README", "")
    """
    parts = name.split(".", 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], "." + parts[1]


def is_reserved_device_name(name: str) -> bool:
    """Check if the base name (before first dot) is a Win32 reserved device name."""
    base, _ = parse_basename(name)
    return base.upper() in RESERVED_NAMES


def has_trailing_dot_or_space(name: str) -> bool:
    """Check if name ends with a dot or space (Win32 may normalize these away)."""
    return name.endswith(" ") or name.endswith(".")


def detect_hazards(
    name: str,
    canonical_path_len: int,
    is_reparse: bool,
) -> list[dict[str, Any]]:
    """Detect all applicable hazards for a filesystem entry name.

    Returns a list of hazard dicts with code, severity, confidence.
    """
    hazards: list[dict[str, Any]] = []

    if is_reparse:
        hazards.append({
            "code": "REPARSE_POINT_PRESENT",
            "severity": "high",
            "confidence": "high",
        })
        return hazards  # don't analyze further for reparse points

    if is_reserved_device_name(name):
        hazards.append({
            "code": "WIN_RESERVED_DEVICE_BASENAME",
            "severity": "high",
            "confidence": "high",
        })

    if has_trailing_dot_or_space(name):
        hazards.append({
            "code": "WIN_TRAILING_DOT_SPACE",
            "severity": "medium",
            "confidence": "high",
        })

    if canonical_path_len > 260:
        hazards.append({
            "code": "WIN_PATH_TOO_LONG",
            "severity": "medium",
            "confidence": "high",
        })

    return hazards
