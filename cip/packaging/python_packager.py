"""Build Python distribution artifacts (wheel/sdist) or a source bundle for applications."""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

from cip.utils import IGNORED_DIRS, run_cmd

BUNDLE_EXCLUDE = IGNORED_DIRS | {"tests", ".coveragerc"}


def build_package(workspace: Path, out_dir: Path, build_wheel: bool = True, name: str = "") -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"artifacts": [], "type": "", "message": ""}
    is_lib = (workspace / "pyproject.toml").exists() or (workspace / "setup.py").exists()

    if is_lib and build_wheel:
        r = run_cmd([sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out_dir), str(workspace)],
                    cwd=workspace, timeout=900)
        if r.ok:
            result["type"] = "python-distribution"
            result["artifacts"] = sorted(p.name for p in out_dir.iterdir() if p.suffix in (".whl", ".gz"))
            result["message"] = "wheel + sdist built"
        else:
            result["message"] = f"python -m build failed: {(r.stderr or r.stdout)[-600:]}"
            result["build_error"] = True

    if not result["artifacts"]:
        # Application (no packaging metadata): ship a clean, versionable source bundle.
        bundle = out_dir / f"{name or workspace.name}-source.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in workspace.rglob("*"):
                parts = set(p.relative_to(workspace).parts)
                if p.is_file() and not parts & BUNDLE_EXCLUDE and not p.name.startswith(".env") \
                        and not any(x.endswith(".egg-info") for x in parts):
                    zf.write(p, p.relative_to(workspace).as_posix())
        result["artifacts"].append(bundle.name)
        result["type"] = result["type"] or "application-source-bundle"
        result["message"] = (result["message"] + "; " if result["message"] else "") + \
            "application repo – primary deployable is the container image; source bundle created"
    return result
