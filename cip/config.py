"""Load config/pipeline.yaml with ${ENV:-default} substitution and optional .env file."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "pipeline.yaml"


_DUPES_WARNED = False


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines. Within the file the LAST occurrence of a key wins (standard .env behaviour);
    variables already set in the real environment are never overwritten."""
    if not path.exists():
        return
    values: dict[str, str] = {}
    dupes: set[str] = set()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        elif " #" in val:                      # inline comment:  KEY=value   # note
            val = val.split(" #", 1)[0].strip()
        if key in values and values[key] != val:
            dupes.add(key)
        values[key] = val
    for key, val in values.items():
        os.environ.setdefault(key, val)
    global _DUPES_WARNED
    if dupes and not _DUPES_WARNED:
        _DUPES_WARNED = True
        import logging
        logging.getLogger("cip.config").warning(
            ".env defines %s more than once – using the LAST value. Remove the duplicates to avoid confusion.",
            ", ".join(sorted(dupes)))


def _subst(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _subst(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v) for v in value]
    return value


def load_config(path: Path | None = None) -> dict:
    load_dotenv(PROJECT_ROOT / ".env")
    path = path or os.getenv("CIP_CONFIG")   # e.g. set CIP_CONFIG=config\my-team.yaml
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    with open(cfg_path, encoding="utf-8") as fh:
        return _subst(yaml.safe_load(fh))
