"""Decide the primary language and whether this pipeline version supports it."""
from __future__ import annotations

SUPPORTED_LANGUAGES = {"Python"}  # V1. Java / JavaScript plug in here later.
_CODE_LANGS = {"Python", "JavaScript", "TypeScript", "Java", "Go", "Ruby", "C#", "PHP", "Rust", "Kotlin"}


def detect_language(repo_scan: dict) -> dict:
    loc = repo_scan.get("lines_of_code", {})
    counts = {k: v for k, v in repo_scan.get("files_by_language", {}).items() if k in _CODE_LANGS}
    if loc:
        primary = max(loc, key=loc.get)
    elif counts:
        primary = max(counts, key=counts.get)
    else:
        primary = "Unknown"
    return {
        "primary_language": primary,
        "languages": counts,
        "supported": primary in SUPPORTED_LANGUAGES,
    }
